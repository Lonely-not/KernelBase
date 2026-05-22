#pragma once
#include <ntddk.h>

// 手动定义所需结构体
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// v1.0.0
PVOID GetKernelBase(void);
PVOID GetKernelVaByRva(ULONG_PTR Rva);

// v1.2.0
PVOID GetKernelExportByName(PCWSTR ModuleName, PCSTR FunctionName);
BOOLEAN IsAddressInKernelImage(PVOID Address);
BOOLEAN IsKernelAddress(PVOID Address);
PVOID GetKernelSectionByName(PCSTR SectionName, PULONG SectionSize);
BOOLEAN IsPatchGuardEnabled(void);

// v1.3.0
PVOID GetModuleBaseByName(PCWSTR ModuleName);
ULONG GetModuleSizeByName(PCWSTR ModuleName);
ULONG GetSystemModuleCount(void);

// v1.4.0
BOOLEAN IsAddressInModule(PVOID Address, PCWSTR ModuleName);
NTSTATUS SafeReadKernelMemory(PVOID Address, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);
PDRIVER_OBJECT GetDriverObjectByName(PCWSTR DriverName);

// v1.5.0 (High-Risk, debug mode required)
PEPROCESS GetProcessObject(HANDLE ProcessId);
PETHREAD GetThreadObject(HANDLE ThreadId);
NTSTATUS WriteKernelMemory(PVOID Address, PVOID Buffer, SIZE_T Size);
NTSTATUS ForceUnloadDriver(PCWSTR ServiceName);
NTSTATUS ForceCloseHandle(HANDLE ProcessId, HANDLE Handle);

// v1.6.0
NTSTATUS ReadProcessMemory(HANDLE ProcessId, PVOID Address, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);
NTSTATUS WriteProcessMemory(HANDLE ProcessId, PVOID Address, PVOID Buffer, SIZE_T Size);
PVOID GetProcessPeb(HANDLE ProcessId);
PVOID GetProcessMainModuleBase(HANDLE ProcessId);
#include "kernelbase.h"
#include <ntimage.h>
#include <ntstrsafe.h>

#define SystemModuleInformation 0x0B
#define PROCESS_QUERY_INFORMATION 0x0400

// 手动声明未公开的 ObReferenceObjectByName
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);

// 手动声明未声明但已导出的函数
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread);
NTSTATUS IoDeleteDriver(PDRIVER_OBJECT DriverObject);
NTSYSAPI NTSTATUS NTAPI ZwDuplicateObject(
    HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options
);

// 用于动态获取父进程 ID 的 API 声明
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);
NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(
    PVOID Object,
    ULONG HandleAttributes,
    PACCESS_STATE PassedAccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PHANDLE Handle
);
// PsProcessType 已在 WDK 头文件中声明，无需 extern

// 手动定义 KAPC_STATE 结构体
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    UCHAR InProgressFlags;
    UCHAR KernelApcInProgress;
    UCHAR KernelApcPending;
    UCHAR UserApcPending;
} KAPC_STATE, *PRKAPC_STATE;

// 声明 KeStackAttachProcess 和 KeUnstackDetachProcess
NTSYSAPI VOID NTAPI KeStackAttachProcess(
    PEPROCESS Process,
    PRKAPC_STATE ApcState
);
NTSYSAPI VOID NTAPI KeUnstackDetachProcess(
    PRKAPC_STATE ApcState
);

// 内部辅助：获取 ZwQuerySystemInformation 指针
static NTSTATUS (*GetZwQuerySystemInformation(void))(ULONG, PVOID, ULONG, PULONG)
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
    return (NTSTATUS (*)(ULONG, PVOID, ULONG, PULONG))MmGetSystemRoutineAddress(&routineName);
}

// ========== v1.0.0 原有函数 ==========

PVOID GetKernelBase(void)
{
    NTSTATUS status;
    PRTL_PROCESS_MODULES pModules = NULL;
    ULONG bufferSize = 0;
    PVOID kernelBase = NULL;
    NTSTATUS (*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = GetZwQuerySystemInformation();
    if (!pZwQuerySystemInformation) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return NULL;

    pModules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'bKgK');
    if (!pModules) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, pModules, bufferSize, NULL);
    if (NT_SUCCESS(status) && pModules->NumberOfModules > 0)
        kernelBase = pModules->Modules[0].ImageBase;

    ExFreePoolWithTag(pModules, 'bKgK');
    return kernelBase;
}

PVOID GetKernelVaByRva(ULONG_PTR Rva)
{
    PVOID kernelBase = GetKernelBase();
    if (!kernelBase) return NULL;
    return (PVOID)((PUCHAR)kernelBase + Rva);
}

// ========== v1.2.0 新增函数 ==========

PVOID GetKernelExportByName(PCWSTR ModuleName, PCSTR FunctionName)
{
    NTSTATUS status;
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    PVOID funcAddr = NULL;
    NTSTATUS (*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = GetZwQuerySystemInformation();
    if (!pZwQuerySystemInformation) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return NULL;

    modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, 'gKwK');
    if (!modules) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, modules, size, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(modules, 'gKwK'); return NULL; }

    PVOID targetBase = NULL;
    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        PCWSTR fullPath = (PCWSTR)modules->Modules[i].FullPathName;
        PCWSTR fileName = wcsrchr(fullPath, L'\\');
        fileName = fileName ? (fileName + 1) : fullPath;
        if (_wcsicmp(fileName, ModuleName) == 0) {
            targetBase = modules->Modules[i].ImageBase;
            break;
        }
    }
    ExFreePoolWithTag(modules, 'gKwK');
    if (!targetBase) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)targetBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)targetBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    ULONG exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)targetBase + exportRva);
    ULONG* names = (ULONG*)((PUCHAR)targetBase + exports->AddressOfNames);
    USHORT* ordinals = (USHORT*)((PUCHAR)targetBase + exports->AddressOfNameOrdinals);
    ULONG* functions = (ULONG*)((PUCHAR)targetBase + exports->AddressOfFunctions);

    for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
        PCSTR name = (PCSTR)((PUCHAR)targetBase + names[i]);
        if (strcmp(name, FunctionName) == 0) {
            funcAddr = (PVOID)((PUCHAR)targetBase + functions[ordinals[i]]);
            break;
        }
    }
    return funcAddr;
}

BOOLEAN IsAddressInKernelImage(PVOID Address)
{
    PVOID kernelBase = GetKernelBase();
    if (!kernelBase) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernelBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)kernelBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    ULONG_PTR start = (ULONG_PTR)kernelBase;
    ULONG_PTR end = start + nt->OptionalHeader.SizeOfImage;
    ULONG_PTR addr = (ULONG_PTR)Address;
    return (addr >= start && addr < end);
}

BOOLEAN IsKernelAddress(PVOID Address)
{
    return ((ULONG_PTR)Address >= 0xFFFF800000000000ULL);
}

PVOID GetKernelSectionByName(PCSTR SectionName, PULONG SectionSize)
{
    PVOID kernelBase = GetKernelBase();
    if (!kernelBase || !SectionSize) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)kernelBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)kernelBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((PCSTR)section[i].Name, SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            *SectionSize = section[i].Misc.VirtualSize;
            return (PVOID)((PUCHAR)kernelBase + section[i].VirtualAddress);
        }
    }
    return NULL;
}

BOOLEAN IsPatchGuardEnabled(void)
{
    UNICODE_STRING varName;
    RtlInitUnicodeString(&varName, L"KdDebuggerEnabled");
    PBOOLEAN pKdDebuggerEnabled = (PBOOLEAN)MmGetSystemRoutineAddress(&varName);
    if (pKdDebuggerEnabled) {
        return (*pKdDebuggerEnabled == FALSE);
    }
    return TRUE;
}

// ========== v1.3.0 新增函数 ==========

PVOID GetModuleBaseByName(PCWSTR ModuleName)
{
    if (!ModuleName) return NULL;
    NTSTATUS status;
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    PVOID targetBase = NULL;
    NTSTATUS (*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = GetZwQuerySystemInformation();
    if (!pZwQuerySystemInformation) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return NULL;

    modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, 'mKwK');
    if (!modules) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, modules, size, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(modules, 'mKwK'); return NULL; }

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        PCWSTR fullPath = (PCWSTR)modules->Modules[i].FullPathName;
        PCWSTR fileName = wcsrchr(fullPath, L'\\');
        fileName = fileName ? (fileName + 1) : fullPath;
        if (_wcsicmp(fileName, ModuleName) == 0) {
            targetBase = modules->Modules[i].ImageBase;
            break;
        }
    }
    ExFreePoolWithTag(modules, 'mKwK');
    return targetBase;
}

ULONG GetModuleSizeByName(PCWSTR ModuleName)
{
    if (!ModuleName) return 0;
    NTSTATUS status;
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG moduleSize = 0;
    NTSTATUS (*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = GetZwQuerySystemInformation();
    if (!pZwQuerySystemInformation) return 0;

    status = pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return 0;

    modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, 'sKwK');
    if (!modules) return 0;

    status = pZwQuerySystemInformation(SystemModuleInformation, modules, size, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(modules, 'sKwK'); return 0; }

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        PCWSTR fullPath = (PCWSTR)modules->Modules[i].FullPathName;
        PCWSTR fileName = wcsrchr(fullPath, L'\\');
        fileName = fileName ? (fileName + 1) : fullPath;
        if (_wcsicmp(fileName, ModuleName) == 0) {
            moduleSize = modules->Modules[i].ImageSize;
            break;
        }
    }
    ExFreePoolWithTag(modules, 'sKwK');
    return moduleSize;
}

ULONG GetSystemModuleCount(void)
{
    NTSTATUS status;
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG count = 0;
    NTSTATUS (*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = GetZwQuerySystemInformation();
    if (!pZwQuerySystemInformation) return 0;

    status = pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return 0;

    modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, 'cKwK');
    if (!modules) return 0;

    status = pZwQuerySystemInformation(SystemModuleInformation, modules, size, NULL);
    if (NT_SUCCESS(status)) {
        count = modules->NumberOfModules;
    }
    ExFreePoolWithTag(modules, 'cKwK');
    return count;
}

// ========== v1.4.0 新增函数 ==========

static PRTL_PROCESS_MODULE_INFORMATION FindModuleEntryByName(PCWSTR ModuleName, PRTL_PROCESS_MODULES *ModulesOut)
{
    NTSTATUS status;
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    NTSTATUS (*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = GetZwQuerySystemInformation();
    if (!pZwQuerySystemInformation) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return NULL;

    modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, size, 'mKwK');
    if (!modules) return NULL;

    status = pZwQuerySystemInformation(SystemModuleInformation, modules, size, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(modules, 'mKwK'); return NULL; }

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        PCWSTR fullPath = (PCWSTR)modules->Modules[i].FullPathName;
        PCWSTR fileName = wcsrchr(fullPath, L'\\');
        fileName = fileName ? (fileName + 1) : fullPath;
        if (_wcsicmp(fileName, ModuleName) == 0) {
            *ModulesOut = modules;
            return &modules->Modules[i];
        }
    }
    ExFreePoolWithTag(modules, 'mKwK');
    return NULL;
}

BOOLEAN IsAddressInModule(PVOID Address, PCWSTR ModuleName)
{
    if (!Address || !ModuleName) return FALSE;
    PRTL_PROCESS_MODULES modules = NULL;
    PRTL_PROCESS_MODULE_INFORMATION entry = FindModuleEntryByName(ModuleName, &modules);
    if (!entry) return FALSE;
    ULONG_PTR start = (ULONG_PTR)entry->ImageBase;
    ULONG_PTR end = start + entry->ImageSize;
    BOOLEAN result = ((ULONG_PTR)Address >= start && (ULONG_PTR)Address < end);
    ExFreePoolWithTag(modules, 'mKwK');
    return result;
}

NTSTATUS SafeReadKernelMemory(PVOID Address, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    SIZE_T copied = 0;
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        RtlCopyMemory(Buffer, Address, Size);
        copied = Size;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (BytesRead) *BytesRead = copied;
    return status;
}

PDRIVER_OBJECT GetDriverObjectByName(PCWSTR DriverName)
{
    if (!DriverName) return NULL;
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, DriverName);
    PDRIVER_OBJECT driver = NULL;
    if (NT_SUCCESS(ObReferenceObjectByName(
        &name, OBJ_CASE_INSENSITIVE, NULL, 0,
        NULL, KernelMode, NULL, (PVOID*)&driver
    ))) {
        ObDereferenceObject(driver);
        return driver;
    }
    return NULL;
}

// ========== v1.5.0 新增函数 ==========

PEPROCESS GetProcessObject(HANDLE ProcessId)
{
    if (ProcessId == NULL) return NULL;
    PEPROCESS eproc = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &eproc))) {
        ObDereferenceObject(eproc);
        return eproc;
    }
    return NULL;
}

PETHREAD GetThreadObject(HANDLE ThreadId)
{
    if (ThreadId == NULL) return NULL;
    PETHREAD ethread = NULL;
    if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &ethread))) {
        ObDereferenceObject(ethread);
        return ethread;
    }
    return NULL;
}

NTSTATUS WriteKernelMemory(PVOID Address, PVOID Buffer, SIZE_T Size)
{
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    PMDL mdl = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;
    MmBuildMdlForNonPagedPool(mdl);
    PVOID mappedAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!mappedAddr) { IoFreeMdl(mdl); return STATUS_UNSUCCESSFUL; }
    RtlCopyMemory(mappedAddr, Buffer, Size);
    MmUnmapLockedPages(mappedAddr, mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}

NTSTATUS ForceUnloadDriver(PCWSTR ServiceName)
{
    if (!ServiceName) return STATUS_INVALID_PARAMETER;
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, ServiceName);
    PDRIVER_OBJECT driver = NULL;
    if (!NT_SUCCESS(ObReferenceObjectByName(
        &name, OBJ_CASE_INSENSITIVE, NULL, 0,
        NULL, KernelMode, NULL, (PVOID*)&driver
    ))) return STATUS_NOT_FOUND;
    IoDeleteDriver(driver);
    ObDereferenceObject(driver);
    return STATUS_SUCCESS;
}

NTSTATUS ForceCloseHandle(HANDLE ProcessId, HANDLE Handle)
{
    if (!ProcessId || !Handle) return STATUS_INVALID_PARAMETER;
    PEPROCESS eproc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &eproc))) return STATUS_NOT_FOUND;
    HANDLE hDup = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    __try {
        status = ZwDuplicateObject(
            NtCurrentProcess(), Handle, eproc, &hDup,
            0, 0, DUPLICATE_CLOSE_SOURCE
        );
        if (NT_SUCCESS(status) && hDup != NULL) ZwClose(hDup);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    ObDereferenceObject(eproc);
    return status;
}

// ========== v1.6.0 新增函数 ==========

PVOID GetProcessPeb(HANDLE ProcessId)
{
    if (ProcessId == NULL) return NULL;
    PEPROCESS eproc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &eproc))) return NULL;
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsGetProcessPeb");
    PVOID (*pfnPsGetProcessPeb)(PEPROCESS) = (PVOID (*)(PEPROCESS))MmGetSystemRoutineAddress(&funcName);
    PVOID peb = NULL;
    if (pfnPsGetProcessPeb) {
        peb = pfnPsGetProcessPeb(eproc);
    }
    ObDereferenceObject(eproc);
    return peb;
}

PVOID GetProcessMainModuleBase(HANDLE ProcessId)
{
    if (ProcessId == NULL) return NULL;
    PVOID peb = GetProcessPeb(ProcessId);
    if (!peb) return NULL;
    __try {
        PVOID ldr = *(PVOID*)((PUCHAR)peb + 0x018);
        if (!ldr) return NULL;
        PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)ldr + 0x010);
        PLIST_ENTRY first = head->Flink;
        if (first == head) return NULL;
        PVOID dllBase = *(PVOID*)((PUCHAR)first + 0x030);
        return dllBase;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

NTSTATUS ReadProcessMemory(HANDLE ProcessId, PVOID Address, PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    PEPROCESS eproc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &eproc))) return STATUS_NOT_FOUND;
    KAPC_STATE apcState;
    KeStackAttachProcess(eproc, &apcState);
    SIZE_T copied = 0;
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        RtlCopyMemory(Buffer, Address, Size);
        copied = Size;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    if (BytesRead) *BytesRead = copied;
    ObDereferenceObject(eproc);
    return status;
}

NTSTATUS WriteProcessMemory(HANDLE ProcessId, PVOID Address, PVOID Buffer, SIZE_T Size)
{
    if (!Address || !Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    PEPROCESS eproc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &eproc))) return STATUS_NOT_FOUND;
    KAPC_STATE apcState;
    KeStackAttachProcess(eproc, &apcState);
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        RtlCopyMemory(Address, Buffer, Size);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(eproc);
    return status;
}

// ========== v1.7.0 新增函数 ==========

PVOID GetThreadTeb(HANDLE ThreadId)
{
    if (ThreadId == NULL) return NULL;
    PETHREAD ethread = NULL;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &ethread))) return NULL;
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsGetThreadTeb");
    PVOID (*pfnPsGetThreadTeb)(PETHREAD) = (PVOID (*)(PETHREAD))MmGetSystemRoutineAddress(&funcName);
    PVOID teb = NULL;
    if (pfnPsGetThreadTeb) {
        teb = pfnPsGetThreadTeb(ethread);
    }
    ObDereferenceObject(ethread);
    return teb;
}

HANDLE GetProcessParentId(HANDLE ProcessId)
{
    if (ProcessId == NULL) return NULL;

    HANDLE hProcess = NULL;
    CLIENT_ID clientId;
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    NTSTATUS status = ZwOpenProcess(
        &hProcess,
        PROCESS_QUERY_INFORMATION,
        &oa,
        &clientId
    );
    if (!NT_SUCCESS(status)) return NULL;

    PROCESS_BASIC_INFORMATION pbi;
    status = ZwQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL
    );

    HANDLE parentPid = NULL;
    if (NT_SUCCESS(status)) {
        parentPid = (HANDLE)pbi.InheritedFromUniqueProcessId;
    }

    ZwClose(hProcess);
    return parentPid;
}

PVOID GetModuleEntryPoint(PCWSTR ModuleName)
{
    if (!ModuleName) return NULL;
    PVOID base = GetModuleBaseByName(ModuleName);
    if (!base) return NULL;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
        ULONG_PTR entryRva = nt->OptionalHeader.AddressOfEntryPoint;
        if (entryRva == 0) return NULL;
        return (PVOID)((PUCHAR)base + entryRva);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

NTSTATUS SafeCompareKernelMemory(PVOID Address1, PVOID Address2, SIZE_T Size, PBOOLEAN Equal)
{
    if (!Address1 || !Address2 || !Equal || Size == 0) return STATUS_INVALID_PARAMETER;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN result = FALSE;
    __try {
        result = (RtlCompareMemory(Address1, Address2, Size) == Size);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    *Equal = result;
    return status;
}
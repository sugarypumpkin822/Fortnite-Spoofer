/*
 * HWID Spoofer - Driver Mapper Module Header
 * KDMapper integration for kernel driver mapping
 */

#ifndef DRIVER_MAPPER_H
#define DRIVER_MAPPER_H

#include "../manager.h"

#ifdef __cplusplus
extern "C" {
#endif

// Vulnerable driver operations
BOOL LoadVulnerableDriver(void);
VOID UnloadVulnerableDriver(void);

// Kernel memory operations
PVOID KM_GetKernelBase(void);
PVOID KM_MapPhysicalMemory(ULONG64 physAddr, SIZE_T size);
VOID KM_UnmapPhysicalMemory(PVOID virtAddr, SIZE_T size);
BOOL KM_CopyKernelMemory(ULONG64 dest, ULONG64 src, SIZE_T size);
BOOL KM_ReadKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
BOOL KM_WriteKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
BOOL KM_ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size);
BOOL KM_WritePhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size);
ULONG64 KM_TranslateLinearAddress(ULONG64 dirBase, ULONG64 virtualAddr);
ULONG64 KM_GetDirectoryTableBase(void);
BOOL KM_WriteToReadOnlyMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);

// Kernel image operations
PVOID KM_GetKernelExport(const char* name);
BOOL KM_ProcessRelocations(PVOID imageBase, PVOID mappedBase, SIZE_T imageSize);
BOOL KM_ResolveImports(PVOID imageBase);
ULONG64 KM_FindCodeCave(SIZE_T needed);
ULONG64 KM_AllocateKernelPool(SIZE_T size);
BOOL KM_CallDriverEntry(ULONG64 entryAddr);
BOOL KM_MapDriverFromMemory(PVOID buffer, DWORD size);

// Driver loading
BOOL LoadSpooferDriver(void);
BOOL UnloadSpooferDriver(void);

#ifdef __cplusplus
}
#endif

#endif // DRIVER_MAPPER_H

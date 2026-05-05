/*
 * Trace Cleaner - Registry Module
 * Removes forensic artifacts from Windows Registry
 */

#ifndef TC_REGISTRY_H
#define TC_REGISTRY_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Registry trace key structure
typedef struct _REG_TRACE_KEY {
    HKEY Root;
    const wchar_t* Path;
    const wchar_t* ValueName;
    BOOL DeleteEntireKey;
} REG_TRACE_KEY;

// Clean registry traces
BOOL TraceClean_RegistryTraces(CLEAN_STATS* Stats);

// Delete a specific registry value
BOOL DeleteRegistryValue(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName);

// Clear USBSTOR device history
BOOL ClearUSBSTORHistory(CLEAN_STATS* Stats);

// Clear Amcache entries for a specific application
BOOL ClearAmcacheEntry(const wchar_t* applicationPath);

// Get list of registry traces that will be cleaned
const REG_TRACE_KEY* GetRegistryTraceList(DWORD* count);

#ifdef __cplusplus
}
#endif

#endif // TC_REGISTRY_H

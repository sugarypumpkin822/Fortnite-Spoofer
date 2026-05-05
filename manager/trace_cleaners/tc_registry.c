/*
 * Trace Cleaner - Registry Module
 * Removes forensic artifacts from Windows Registry
 */

#include "tc_registry.h"
#include <stdio.h>
#include <string.h>

// List of registry locations to clean
static const REG_TRACE_KEY g_RegTraceKeys[] = {
    // UserAssist - tracks program execution
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", NULL, TRUE},
    
    // RunMRU - tracks Run dialog history
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", NULL, TRUE},
    
    // RecentDocs - tracks recently opened documents
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", NULL, TRUE},
    
    // ComDlg32 - OpenSavePidlMRU and LastVisitedPidlMRU
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", NULL, TRUE},
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", NULL, TRUE},
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRULegacy", NULL, TRUE},
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRULegacy", NULL, TRUE},
    
    // Feature usage tracking
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage", NULL, TRUE},
    
    // TypedPaths - Explorer address bar history
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", NULL, TRUE},
    
    // WordWheelQuery - search history
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery", NULL, TRUE},
    
    // Search history
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentItems", NULL, TRUE},
    
    // BagMRU - folder view settings (contains folder paths)
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\Shell\\BagMRU", NULL, TRUE},
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\Shell\\Bags", NULL, TRUE},
    
    // StreamMRU - application file dialog history
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StreamMRU", NULL, TRUE},
    
    // MountPoints2 - network drive history
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", NULL, TRUE},
    
    // Last logged on user
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI", L"LastLoggedOnUser", FALSE},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI", L"LastLoggedOnSAMUser", FALSE},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI", L"LastLoggedOnUserSID", FALSE},
    
    // Prefetch tracking
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"BootId", FALSE},
    
    // Application compatibility - ShimCache/AppCompatCache
    {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", NULL, TRUE},
    
    // PowerShell history
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ConsoleHost\\History", NULL, TRUE},
};

BOOL DeleteRegistryValue(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName) {
    if (!subKey || !valueName) return FALSE;
    
    HKEY hKey;
    LONG status = RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) return FALSE;
    
    status = RegDeleteValueW(hKey, valueName);
    RegCloseKey(hKey);
    
    return status == ERROR_SUCCESS;
}

BOOL ClearUSBSTORHistory(CLEAN_STATS* Stats) {
    BOOL result = FALSE;
    
    HKEY hUsbStor;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                      0, KEY_READ | KEY_WRITE, &hUsbStor) != ERROR_SUCCESS) {
        return FALSE;
    }
    
    wchar_t subKeyName[256];
    DWORD subKeyIndex = 0;
    DWORD nameLen = 256;
    
    while (RegEnumKeyExW(hUsbStor, subKeyIndex++, subKeyName, &nameLen,
                         NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        HKEY hDeviceKey;
        wchar_t devicePath[512];
        _snwprintf_s(devicePath, 512, 
                      L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\%s", subKeyName);
        
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, devicePath, 0,
                          KEY_READ | KEY_WRITE, &hDeviceKey) == ERROR_SUCCESS) {
            wchar_t instanceName[256];
            DWORD instanceIndex = 0;
            DWORD instanceLen = 256;
            
            while (RegEnumKeyExW(hDeviceKey, instanceIndex++, instanceName,
                               &instanceLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                HKEY hInstance;
                wchar_t instancePath[768];
                _snwprintf_s(instancePath, 768, L"%s\\%s", devicePath, instanceName);
                
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, instancePath, 0,
                                  KEY_SET_VALUE, &hInstance) == ERROR_SUCCESS) {
                    RegDeleteValueW(hInstance, L"FriendlyName");
                    RegDeleteValueW(hInstance, L"DeviceDesc");
                    RegDeleteValueW(hInstance, L"LocationInformation");
                    RegCloseKey(hInstance);
                    Stats->RegistryValuesDeleted++;
                    result = TRUE;
                }
                instanceLen = 256;
            }
            RegCloseKey(hDeviceKey);
        }
        nameLen = 256;
    }
    
    RegCloseKey(hUsbStor);
    return result;
}

BOOL ClearAmcacheEntry(const wchar_t* applicationPath) {
    // Amcache.hve is a registry hive that tracks application execution
    // Clearing it requires taking ownership - this is a placeholder
    // for the actual implementation which would need SYSTEM privileges
    (void)applicationPath;
    return TRUE;
}

const REG_TRACE_KEY* GetRegistryTraceList(DWORD* count) {
    if (count) {
        *count = sizeof(g_RegTraceKeys) / sizeof(g_RegTraceKeys[0]);
    }
    return g_RegTraceKeys;
}

BOOL TraceClean_RegistryTraces(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    DWORD keyCount = sizeof(g_RegTraceKeys) / sizeof(g_RegTraceKeys[0]);
    
    for (DWORD i = 0; i < keyCount; i++) {
        if (g_RegTraceKeys[i].DeleteEntireKey) {
            // Try to delete the entire key
            LONG status = RegDeleteTreeW(g_RegTraceKeys[i].Root, g_RegTraceKeys[i].Path);
            if (status == ERROR_SUCCESS) {
                Stats->RegistryKeysDeleted++;
            }
        } else if (g_RegTraceKeys[i].ValueName != NULL) {
            // Delete specific value
            if (DeleteRegistryValue(g_RegTraceKeys[i].Root, 
                                   g_RegTraceKeys[i].Path, 
                                   g_RegTraceKeys[i].ValueName)) {
                Stats->RegistryKeysDeleted++;
            }
        }
        
        // Clear USBSTOR device serial numbers when we encounter USBSTOR entry
        if (wcsstr(g_RegTraceKeys[i].Path, L"USBSTOR") != NULL) {
            ClearUSBSTORHistory(Stats);
        }
    }
    
    return result;
}

/*
 * HWID Spoofer - Trace Cleaner Module
 * 
 * Comprehensive system trace cleaning to remove forensic artifacts:
 * - Windows Event Logs (Application, System, Security, Setup, ForwardedEvents)
 * - Registry traces (UserAssist, RunMRU, RecentDocs, OpenSavePidlMRU)
 * - File system artifacts (Prefetch, Recent Items, Jump Lists, Temp files)
 * - Browser traces (if applicable)
 * - USN Journal cleanup
 * - Superfetch/Search indexer data
 * - Shellbags and thumbnail cache
 */

#include "trace_cleaner.h"

#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlobj.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include <winevt.h>
#include <werapi.h>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// ==================== FORWARD DECLARATIONS ====================

BOOL TraceClean_EventLogs(CLEAN_STATS* Stats);
BOOL TraceClean_RegistryTraces(CLEAN_STATS* Stats);
BOOL TraceClean_Prefetch(CLEAN_STATS* Stats);
BOOL TraceClean_RecentItems(CLEAN_STATS* Stats);
BOOL TraceClean_JumpLists(CLEAN_STATS* Stats);
BOOL TraceClean_TempFiles(CLEAN_STATS* Stats);
BOOL TraceClean_UsnJournal(CLEAN_STATS* Stats);
BOOL TraceClean_Thumbnails(CLEAN_STATS* Stats);
BOOL TraceClean_Shellbags(CLEAN_STATS* Stats);
BOOL TraceClean_BrowserTraces(CLEAN_STATS* Stats);
BOOL TraceClean_WERReports(CLEAN_STATS* Stats);
BOOL TraceClean_SearchIndex(CLEAN_STATS* Stats);
BOOL TraceClean_Superfetch(CLEAN_STATS* Stats);

static void SecureWipeFileInternal(const wchar_t* path);
static BOOL DeleteDirectoryRecursive(const wchar_t* path, CLEAN_STATS* Stats);

// ==================== EVENT LOG CLEANER ====================

/*
 * Clear Windows Event Logs using EvtClearLog
 */
BOOL TraceClean_EventLogs(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    const wchar_t* channels[] = {
        L"Application",
        L"System",
        L"Security",
        L"Setup",
        L"ForwardedEvents",
        L"HardwareEvents",
        L"Microsoft-Windows-PowerShell/Operational",
        L"Microsoft-Windows-Sysmon/Operational",
        L"Microsoft-Windows-TaskScheduler/Operational",
        L"Microsoft-Windows-Windows Defender/Operational",
        L"Microsoft-Windows-Windows Update/Operational",
        L"Microsoft-Windows-Application-Experience/Program-Inventory",
        L"Microsoft-Windows-Application-Experience/Program-Telemetry",
        L"Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
        L"Microsoft-Windows-CodeIntegrity/Operational",
        L"Microsoft-Windows-DeviceGuard/Operational",
        L"Microsoft-Windows-Security-Mitigations/KernelMode",
        L"Microsoft-Windows-Security-Mitigations/UserMode",
        L"Microsoft-Windows-Storage-Storport/Operational",
        L"Microsoft-Windows-TPM/Operational",
        L"Microsoft-Windows-AppLocker/EXE and DLL",
        L"Microsoft-Windows-AppLocker/MSI and Script",
        L"Microsoft-Windows-AppLocker/Packaged app-Execution",
        L"Microsoft-Windows-AppLocker/Packaged app-Deployment",
        L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        L"Microsoft-Windows-NetworkProfile/Operational",
        L"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
        L"Microsoft-Windows-Bits-Client/Operational",
        L"Microsoft-Windows-Bits-Client/Analytic",
        L"Microsoft-Windows-Dhcp-Client/Admin",
        L"Microsoft-Windows-Dhcp-Client/Operational",
        L"Microsoft-Windows-DNS-Client/Operational",
        L"Microsoft-Windows-GroupPolicy/Operational",
        L"Microsoft-Windows-Kernel-Boot/Operational",
        L"Microsoft-Windows-Kernel-PnP/Operational",
        L"Microsoft-Windows-Kernel-ShimEngine/Operational",
        L"Microsoft-Windows-User Profile Service/Operational",
        L"Microsoft-Windows-Windows Defender/WHC",
        L"Setup",
        L"Windows PowerShell"
    };
    
    DWORD channelCount = sizeof(channels) / sizeof(channels[0]);
    
    for (DWORD i = 0; i < channelCount; i++) {
        EVT_HANDLE hChannel = EvtOpenChannelEnum(NULL, NULL);
        if (hChannel) {
            EvtClose(hChannel);
        }
        
        // Try to clear the log
        if (EvtClearLog(NULL, channels[i], NULL, 0)) {
            Stats->EventLogsCleared++;
        }
        
        // Also try to backup and clear using wevtutil command
        wchar_t cmdLine[512];
        swprintf_s(cmdLine, sizeof(cmdLine) / sizeof(wchar_t),
                   L"wevtutil cl \"%s\" 2>nul", channels[i]);
        _wsystem(cmdLine);
    }
    
    // Clear Event Log files directly (backup approach)
    wchar_t eventLogPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\System32\winevt\Logs", eventLogPath, MAX_PATH);
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\*.evtx", eventLogPath);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            // Stop Event Log service temporarily
            SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
            if (hScm) {
                SC_HANDLE hService = OpenServiceW(hScm, L"EventLog", SERVICE_STOP | SERVICE_START);
                if (hService) {
                    SERVICE_STATUS status;
                    ControlService(hService, SERVICE_CONTROL_STOP, &status);
                    Sleep(500);
                    
                    // Delete or truncate the log file
                    wchar_t fullPath[MAX_PATH];
                    swprintf_s(fullPath, MAX_PATH, L"%s\%s", eventLogPath, findData.cFileName);
                    
                    HANDLE hFile = CreateFileW(fullPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                               TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        // Write minimal valid EVTX header
                        BYTE evtxHeader[4096] = {0};
                        evtxHeader[0] = 0x45; // 'E'
                        evtxHeader[1] = 0x6C; // 'l'
                        evtxHeader[2] = 0x66; // 'f'
                        evtxHeader[3] = 0x46; // 'F'
                        evtxHeader[4] = 0x69; // 'i'
                        evtxHeader[5] = 0x6C; // 'l'
                        evtxHeader[6] = 0x65; // 'e'
                        evtxHeader[7] = 0x00;
                        
                        DWORD written;
                        WriteFile(hFile, evtxHeader, 4096, &written, NULL);
                        CloseHandle(hFile);
                        Stats->EventLogsCleared++;
                    }
                    
                    // Restart service
                    StartService(hService, 0, NULL);
                    CloseServiceHandle(hService);
                }
                CloseServiceHandle(hScm);
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    return result;
}

// ==================== REGISTRY TRACE CLEANER ====================

typedef struct _REG_TRACE_KEY {
    HKEY Root;
    const wchar_t* Path;
    const wchar_t* ValueName;
    BOOL DeleteEntireKey;
} REG_TRACE_KEY;

BOOL TraceClean_RegistryTraces(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // List of registry locations to clean
    const REG_TRACE_KEY regKeys[] = {
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
        
        // System profile list - tracks all user SIDs
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", NULL, FALSE}, // Don't delete, just note
        
        // USB device history
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", NULL, FALSE},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USB", NULL, FALSE},
        
        // Mounted devices
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\MountedDevices", NULL, FALSE},
        
        // Prefetch tracking
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", L"BootId", FALSE},
        
        // Application compatibility - ShimCache/AppCompatCache
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", NULL, TRUE},
        
        // Amcache.hve tracks
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppCompatFlags\\Amcache", NULL, FALSE},
        
        // ProgramDataUpdater tracks
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Application-Experience\\Program-Data-Updater", NULL, TRUE},
        
        // PowerShell history
        {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ConsoleHost\\History", NULL, TRUE},
    };
    
    DWORD keyCount = sizeof(regKeys) / sizeof(regKeys[0]);
    
    for (DWORD i = 0; i < keyCount; i++) {
        HKEY hKey;
        DWORD disposition;
        
        if (regKeys[i].DeleteEntireKey) {
            // Try to delete the entire key
            LONG status = RegDeleteTreeW(regKeys[i].Root, regKeys[i].Path);
            if (status == ERROR_SUCCESS) {
                Stats->RegistryKeysDeleted++;
            }
        } else if (regKeys[i].ValueName != NULL) {
            // Delete specific value
            LONG status = RegOpenKeyExW(regKeys[i].Root, regKeys[i].Path, 0,
                                          KEY_SET_VALUE, &hKey);
            if (status == ERROR_SUCCESS) {
                status = RegDeleteValueW(hKey, regKeys[i].ValueName);
                if (status == ERROR_SUCCESS) {
                    Stats->RegistryKeysDeleted++;
                }
                RegCloseKey(hKey);
            }
        }
        
        // Clear USBSTOR device serial numbers
        if (wcsstr(regKeys[i].Path, L"USBSTOR") != NULL) {
            HKEY hUsbStor;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                              0, KEY_READ | KEY_WRITE, &hUsbStor) == ERROR_SUCCESS) {
                wchar_t subKeyName[256];
                DWORD subKeyIndex = 0;
                DWORD nameLen = 256;
                
                while (RegEnumKeyExW(hUsbStor, subKeyIndex++, subKeyName, &nameLen,
                                     NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    HKEY hDeviceKey;
                    wchar_t devicePath[512];
                    swprintf_s(devicePath, 512, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\%s", subKeyName);
                    
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, devicePath, 0,
                                      KEY_READ | KEY_WRITE, &hDeviceKey) == ERROR_SUCCESS) {
                        wchar_t instanceName[256];
                        DWORD instanceIndex = 0;
                        DWORD instanceLen = 256;
                        
                        while (RegEnumKeyExW(hDeviceKey, instanceIndex++, instanceName,
                                           &instanceLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                            // Delete FriendlyName and other identifying values
                            HKEY hInstance;
                            wchar_t instancePath[768];
                            swprintf_s(instancePath, 768, L"%s\\%s", devicePath, instanceName);
                            
                            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, instancePath, 0,
                                              KEY_SET_VALUE, &hInstance) == ERROR_SUCCESS) {
                                RegDeleteValueW(hInstance, L"FriendlyName");
                                RegDeleteValueW(hInstance, L"DeviceDesc");
                                RegDeleteValueW(hInstance, L"LocationInformation");
                                RegCloseKey(hInstance);
                            }
                            instanceLen = 256;
                        }
                        RegCloseKey(hDeviceKey);
                    }
                    nameLen = 256;
                }
                RegCloseKey(hUsbStor);
            }
        }
    }
    
    // Clear Amcache.hve entries related to our process
    // This requires taking ownership of the registry hive
    
    return result;
}

// ==================== PREFETCH CLEANER ====================

BOOL TraceClean_Prefetch(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    wchar_t prefetchPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch", prefetchPath, MAX_PATH);
    
    // Stop Prefetch service if running
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm) {
        SC_HANDLE hSysMain = OpenServiceW(hScm, L"SysMain", SERVICE_STOP);
        if (hSysMain) {
            SERVICE_STATUS status;
            ControlService(hSysMain, SERVICE_CONTROL_STOP, &status);
            CloseServiceHandle(hSysMain);
            Sleep(500);
        }
        CloseServiceHandle(hScm);
    }
    
    // Delete all .pf files
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\\*.pf", prefetchPath);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            // Skip directories
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                continue;
            }
            
            wchar_t fullPath[MAX_PATH];
            swprintf_s(fullPath, MAX_PATH, L"%s\\%s", prefetchPath, findData.cFileName);
            
            // Secure wipe and delete
            SecureWipeFileInternal(fullPath);
            
            if (DeleteFileW(fullPath)) {
                Stats->FilesDeleted++;
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    // Delete ReadyBoot trace files
    wchar_t readyBootPath[MAX_PATH];
    swprintf_s(readyBootPath, MAX_PATH, L"%s\\ReadyBoot", prefetchPath);
    DeleteDirectoryRecursive(readyBootPath, Stats);
    
    // Clear layout.ini
    wchar_t layoutPath[MAX_PATH];
    swprintf_s(layoutPath, MAX_PATH, L"%s\\layout.ini", prefetchPath);
    SecureWipeFileInternal(layoutPath);
    DeleteFileW(layoutPath);
    
    Stats->FoldersCleaned++;
    
    return result;
}

// ==================== RECENT ITEMS CLEANER ====================

BOOL TraceClean_RecentItems(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    wchar_t recentPaths[][MAX_PATH] = {
        L"%APPDATA%\\Microsoft\\Windows\\Recent",
        L"%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations",
        L"%APPDATA%\\Microsoft\\Windows\\Recent\\CustomDestinations",
    };
    
    for (int i = 0; i < sizeof(recentPaths) / sizeof(recentPaths[0]); i++) {
        wchar_t expandedPath[MAX_PATH];
        ExpandEnvironmentStringsW(recentPaths[i], expandedPath, MAX_PATH);
        DeleteDirectoryRecursive(expandedPath, Stats);
    }
    
    // Also clean Office recent files
    HKEY hOfficeKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Office\\16.0\\Word\\File MRU",
                      0, KEY_READ | KEY_WRITE, &hOfficeKey) == ERROR_SUCCESS) {
        RegDeleteTreeW(hOfficeKey, NULL);
        RegCloseKey(hOfficeKey);
    }
    
    // Clear Windows RecentApps
    HKEY hRecentApps;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps",
                      0, KEY_READ | KEY_WRITE, &hRecentApps) == ERROR_SUCCESS) {
        RegDeleteTreeW(hRecentApps, NULL);
        RegCloseKey(hRecentApps);
    }
    
    return result;
}

// ==================== JUMPLISTS CLEANER ====================

BOOL TraceClean_JumpLists(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    wchar_t jumpListPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%APPDATA%\\Microsoft\\Windows\\Recent", jumpListPath, MAX_PATH);
    
    // AutomaticDestinations
    wchar_t autoDestPath[MAX_PATH];
    swprintf_s(autoDestPath, MAX_PATH, L"%s\\AutomaticDestinations", jumpListPath);
    DeleteDirectoryRecursive(autoDestPath, Stats);
    
    // CustomDestinations
    wchar_t customDestPath[MAX_PATH];
    swprintf_s(customDestPath, MAX_PATH, L"%s\\CustomDestinations", jumpListPath);
    DeleteDirectoryRecursive(customDestPath, Stats);
    
    return result;
}

// ==================== TEMP FILES CLEANER ====================

BOOL TraceClean_TempFiles(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Get temp directories
    wchar_t tempPaths[5][MAX_PATH];
    
    GetTempPathW(MAX_PATH, tempPaths[0]);
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Temp", tempPaths[1], MAX_PATH);
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Temp", tempPaths[2], MAX_PATH);
    ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Windows\\WER", tempPaths[3], MAX_PATH);
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache", tempPaths[4], MAX_PATH);
    
    for (int i = 0; i < 5; i++) {
        DeleteDirectoryRecursive(tempPaths[i], Stats);
    }
    
    // Clear Windows Error Reporting local dumps
    wchar_t werLocalPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Windows\\WER", werLocalPath, MAX_PATH);
    DeleteDirectoryRecursive(werLocalPath, Stats);
    
    return result;
}

// ==================== USN JOURNAL CLEANER ====================

/*
 * USN (Update Sequence Number) Journal tracks all file system changes
 * This can reveal file creation, modification, and deletion activity
 */
BOOL TraceClean_UsnJournal(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Get all volume paths
    wchar_t volumeName[MAX_PATH];
    HANDLE hVolume = FindFirstVolumeW(volumeName, MAX_PATH);
    
    if (hVolume == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    do {
        // Skip system reserved volumes
        if (wcsstr(volumeName, L"\\?\\HarddiskVolume") == NULL) {
            continue;
        }
        
        // Open the volume
        HANDLE hDevice = CreateFileW(volumeName, GENERIC_READ | GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                     OPEN_EXISTING, 0, NULL);
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            continue;
        }
        
        // Delete USN journal
        DWORD bytesReturned;
        DELETE_USN_JOURNAL_DATA delUsn = {0};
        delUsn.UsnJournalID = 0;  // 0 means current journal
        delUsn.DeleteFlags = USN_DELETE_FLAG_DELETE;
        
        BOOL deleteResult = DeviceIoControl(hDevice, FSCTL_DELETE_USN_JOURNAL,
                                            &delUsn, sizeof(delUsn),
                                            NULL, 0, &bytesReturned, NULL);
        
        if (deleteResult) {
            Stats->UsnEntriesModified++;
            
            // Create a new empty journal with smaller size
            CREATE_USN_JOURNAL_DATA createUsn = {0};
            createUsn.MaximumSize = 0x100000;  // 1MB
            createUsn.AllocationDelta = 0x10000;  // 64KB
            
            DeviceIoControl(hDevice, FSCTL_CREATE_USN_JOURNAL,
                            &createUsn, sizeof(createUsn),
                            NULL, 0, &bytesReturned, NULL);
        }
        
        CloseHandle(hDevice);
    } while (FindNextVolumeW(hVolume, volumeName, MAX_PATH));
    
    FindVolumeClose(hVolume);
    return result;
}

// ==================== THUMBNAIL CACHE CLEANER ====================

BOOL TraceClean_Thumbnails(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Stop Windows Explorer thumbnail cache
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    
    // Clear thumbnail cache path
    wchar_t thumbPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer",
                              thumbPath, MAX_PATH);
    
    // Delete thumbcache files
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\\thumbcache_*.db", thumbPath);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wchar_t fullPath[MAX_PATH];
            swprintf_s(fullPath, MAX_PATH, L"%s\\%s", thumbPath, findData.cFileName);
            SecureWipeFileInternal(fullPath);
            if (DeleteFileW(fullPath)) {
                Stats->FilesDeleted++;
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    // Clear icon cache
    wchar_t iconCachePath[MAX_PATH];
    swprintf_s(iconCachePath, MAX_PATH, L"%s\\iconcache_*.db", thumbPath);
    
    hFind = FindFirstFileW(iconCachePath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wchar_t fullPath[MAX_PATH];
            swprintf_s(fullPath, MAX_PATH, L"%s\\%s", thumbPath, findData.cFileName);
            SecureWipeFileInternal(fullPath);
            DeleteFileW(fullPath);
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    return result;
}

// ==================== SHELLBAGS CLEANER ====================

BOOL TraceClean_Shellbags(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Delete BagMRU and Bags keys
    const wchar_t* shellbagKeys[] = {
        L"Software\\Microsoft\\Windows\\Shell\\BagMRU",
        L"Software\\Microsoft\\Windows\\Shell\\Bags",
        L"Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
        L"Software\\Microsoft\\Windows\\ShellNoRoam\\Bags",
        L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
    };
    
    for (int i = 0; i < sizeof(shellbagKeys) / sizeof(shellbagKeys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, shellbagKeys[i], 0,
                          KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegDeleteTreeW(hKey, NULL);
            RegCloseKey(hKey);
            Stats->RegistryKeysDeleted++;
        }
    }
    
    // Also clean desktop.ini files that store folder view settings
    // This is done in the temp files cleaner
    
    return result;
}

// ==================== BROWSER TRACES CLEANER ====================

BOOL TraceClean_BrowserTraces(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Chrome
    wchar_t chromePaths[][MAX_PATH] = {
        L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache",
        L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
        L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies",
        L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
        L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Web Data",
        L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
    };
    
    // Edge
    wchar_t edgePaths[][MAX_PATH] = {
        L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache",
        L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History",
        L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cookies",
    };
    
    // Firefox
    wchar_t firefoxPaths[][MAX_PATH] = {
        L"%APPDATA%\\Mozilla\\Firefox\\Profiles",
    };
    
    // Clean Chrome
    for (int i = 0; i < sizeof(chromePaths) / sizeof(chromePaths[0]); i++) {
        wchar_t expanded[MAX_PATH];
        ExpandEnvironmentStringsW(chromePaths[i], expanded, MAX_PATH);
        DeleteDirectoryRecursive(expanded, Stats);
    }
    
    // Clean Edge
    for (int i = 0; i < sizeof(edgePaths) / sizeof(edgePaths[0]); i++) {
        wchar_t expanded[MAX_PATH];
        ExpandEnvironmentStringsW(edgePaths[i], expanded, MAX_PATH);
        DeleteDirectoryRecursive(expanded, Stats);
    }
    
    // Clean Firefox
    for (int i = 0; i < sizeof(firefoxPaths) / sizeof(firefoxPaths[0]); i++) {
        wchar_t expanded[MAX_PATH];
        ExpandEnvironmentStringsW(firefoxPaths[i], expanded, MAX_PATH);
        DeleteDirectoryRecursive(expanded, Stats);
    }
    
    return result;
}

// ==================== WER (ERROR REPORTING) CLEANER ====================

BOOL TraceClean_WERReports(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Clear WER queue
    WER_REPORT_INFORMATION reportInfo;
    RtlZeroMemory(&reportInfo, sizeof(reportInfo));
    reportInfo.dwSize = sizeof(reportInfo);
    
    // Delete WER report files
    wchar_t werPaths[][MAX_PATH] = {
        L"%ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive",
        L"%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue",
        L"%ProgramData%\\Microsoft\\Windows\\WER\\Temp",
        L"%LOCALAPPDATA%\\Microsoft\\Windows\\WER",
        L"%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportArchive",
        L"%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportQueue",
    };
    
    for (int i = 0; i < sizeof(werPaths) / sizeof(werPaths[0]); i++) {
        wchar_t expanded[MAX_PATH];
        ExpandEnvironmentStringsW(werPaths[i], expanded, MAX_PATH);
        DeleteDirectoryRecursive(expanded, Stats);
    }
    
    // Clear WER registry
    const wchar_t* werRegKeys[] = {
        L"Software\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps",
        L"Software\\Microsoft\\Windows\\Windows Error Reporting\\Store",
    };
    
    for (int i = 0; i < sizeof(werRegKeys) / sizeof(werRegKeys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, werRegKeys[i], 0,
                          KEY_READ | KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegDeleteTreeW(hKey, NULL);
            RegCloseKey(hKey);
        }
    }
    
    return result;
}

// ==================== SEARCH INDEX CLEANER ====================

BOOL TraceClean_SearchIndex(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Stop Windows Search service
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm) {
        SC_HANDLE hSearch = OpenServiceW(hScm, L"WSearch", SERVICE_STOP);
        if (hSearch) {
            SERVICE_STATUS status;
            ControlService(hSearch, SERVICE_CONTROL_STOP, &status);
            CloseServiceHandle(hSearch);
            Sleep(1000);
        }
        CloseServiceHandle(hScm);
    }
    
    // Delete Windows Search index
    wchar_t searchIndexPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows",
                              searchIndexPath, MAX_PATH);
    DeleteDirectoryRecursive(searchIndexPath, Stats);
    
    // Clear search history
    HKEY hSearchKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
                      0, KEY_READ | KEY_WRITE, &hSearchKey) == ERROR_SUCCESS) {
        RegDeleteTreeW(hSearchKey, NULL);
        RegCloseKey(hSearchKey);
    }
    
    // Restart search service
    if (hScm) {
        SC_HANDLE hSearch = OpenServiceW(hScm, L"WSearch", SERVICE_START);
        if (hSearch) {
            StartService(hSearch, 0, NULL);
            CloseServiceHandle(hSearch);
        }
    }
    
    return result;
}

// ==================== SUPERFETCH CLEANER ====================

BOOL TraceClean_Superfetch(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Stop SysMain (Superfetch)
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm) {
        SC_HANDLE hSysMain = OpenServiceW(hScm, L"SysMain", SERVICE_STOP);
        if (hSysMain) {
            SERVICE_STATUS status;
            ControlService(hSysMain, SERVICE_CONTROL_STOP, &status);
            CloseServiceHandle(hSysMain);
            Sleep(500);
        }
    }
    
    // Delete Superfetch database
    wchar_t superfetchPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch\\*.db",
                              superfetchPath, MAX_PATH);
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(superfetchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        wchar_t prefPath[MAX_PATH];
        ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch", prefPath, MAX_PATH);
        
        do {
            wchar_t fullPath[MAX_PATH];
            swprintf_s(fullPath, MAX_PATH, L"%s\\%s", prefPath, findData.cFileName);
            SecureWipeFileInternal(fullPath);
            DeleteFileW(fullPath);
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    // Restart SysMain
    if (hScm) {
        SC_HANDLE hSysMain = OpenServiceW(hScm, L"SysMain", SERVICE_START);
        if (hSysMain) {
            StartService(hSysMain, 0, NULL);
            CloseServiceHandle(hSysMain);
        }
        CloseServiceHandle(hScm);
    }
    
    return result;
}

// ==================== HELPER FUNCTIONS ====================

static void SecureWipeFileInternal(const wchar_t* path) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return;
    }
    
    // Don't wipe files larger than 100MB (performance)
    if (fileSize.QuadPart > 100 * 1024 * 1024) {
        CloseHandle(hFile);
        return;
    }
    
    // Allocate wipe buffer
    const SIZE_T bufferSize = 64 * 1024;  // 64KB
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) {
        CloseHandle(hFile);
        return;
    }
    
    // Pass 1: Zeros
    RtlZeroMemory(buffer, bufferSize);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    for (LONGLONG offset = 0; offset < fileSize.QuadPart; offset += bufferSize) {
        DWORD toWrite = (DWORD)min(bufferSize, fileSize.QuadPart - offset);
        WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
    }
    FlushFileBuffers(hFile);
    
    // Pass 2: Ones
    RtlFillMemory(buffer, bufferSize, 0xFF);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    for (LONGLONG offset = 0; offset < fileSize.QuadPart; offset += bufferSize) {
        DWORD toWrite = (DWORD)min(bufferSize, fileSize.QuadPart - offset);
        WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
    }
    FlushFileBuffers(hFile);
    
    // Pass 3: Random
    for (SIZE_T i = 0; i < bufferSize; i++) {
        buffer[i] = (BYTE)(rand() & 0xFF);
    }
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    for (LONGLONG offset = 0; offset < fileSize.QuadPart; offset += bufferSize) {
        DWORD toWrite = (DWORD)min(bufferSize, fileSize.QuadPart - offset);
        WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
    }
    FlushFileBuffers(hFile);
    
    free(buffer);
    CloseHandle(hFile);
}

static BOOL DeleteDirectoryRecursive(const wchar_t* path, CLEAN_STATS* Stats) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    
    swprintf_s(searchPath, MAX_PATH, L"%s\\*", path);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    do {
        if (wcscmp(findData.cFileName, L".") == 0 ||
            wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        
        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, MAX_PATH, L"%s\\%s", path, findData.cFileName);
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteDirectoryRecursive(fullPath, Stats);
            RemoveDirectoryW(fullPath);
        } else {
            SecureWipeFileInternal(fullPath);
            if (DeleteFileW(fullPath)) {
                Stats->FilesDeleted++;
            }
        }
    } while (FindNextFileW(hFind, &findData));
    
    FindClose(hFind);
    return TRUE;
}

// ==================== MAIN CLEAN INTERFACE ====================

/*
 * Run all trace cleaning operations
 */
BOOL TraceClean_RunAll(CLEAN_STATS* Stats) {
    RtlZeroMemory(Stats, sizeof(CLEAN_STATS));
    
    BOOL result = TRUE;
    
    // Disable file system redirection on x64 systems
    PVOID oldValue = NULL;
    Wow64DisableWow64FsRedirection(&oldValue);
    
    result &= TraceClean_EventLogs(Stats);
    result &= TraceClean_RegistryTraces(Stats);
    result &= TraceClean_Prefetch(Stats);
    result &= TraceClean_RecentItems(Stats);
    result &= TraceClean_JumpLists(Stats);
    result &= TraceClean_TempFiles(Stats);
    result &= TraceClean_UsnJournal(Stats);
    result &= TraceClean_Thumbnails(Stats);
    result &= TraceClean_Shellbags(Stats);
    result &= TraceClean_BrowserTraces(Stats);
    result &= TraceClean_WERReports(Stats);
    result &= TraceClean_SearchIndex(Stats);
    result &= TraceClean_Superfetch(Stats);
    
    // Restore file system redirection
    if (oldValue != NULL) {
        Wow64RevertWow64FsRedirection(oldValue);
    }
    
    return result;
}

/*
 * Run selective trace cleaning based on category flags
 */
BOOL TraceClean_RunCategory(DWORD CategoryFlags, CLEAN_STATS* Stats) {
    RtlZeroMemory(Stats, sizeof(CLEAN_STATS));
    
    BOOL result = TRUE;
    
    PVOID oldValue = NULL;
    Wow64DisableWow64FsRedirection(&oldValue);
    
    if (CategoryFlags & TRACE_EVENT_LOGS) {
        result &= TraceClean_EventLogs(Stats);
    }
    if (CategoryFlags & TRACE_REGISTRY) {
        result &= TraceClean_RegistryTraces(Stats);
    }
    if (CategoryFlags & TRACE_PREFETCH) {
        result &= TraceClean_Prefetch(Stats);
    }
    if (CategoryFlags & TRACE_RECENT_ITEMS) {
        result &= TraceClean_RecentItems(Stats);
    }
    if (CategoryFlags & TRACE_JUMPLISTS) {
        result &= TraceClean_JumpLists(Stats);
    }
    if (CategoryFlags & TRACE_TEMP_FILES) {
        result &= TraceClean_TempFiles(Stats);
    }
    if (CategoryFlags & TRACE_USN_JOURNAL) {
        result &= TraceClean_UsnJournal(Stats);
    }
    if (CategoryFlags & TRACE_THUMBNAILS) {
        result &= TraceClean_Thumbnails(Stats);
    }
    if (CategoryFlags & TRACE_SHELLBAGS) {
        result &= TraceClean_Shellbags(Stats);
    }
    if (CategoryFlags & TRACE_BROWSER) {
        result &= TraceClean_BrowserTraces(Stats);
    }
    if (CategoryFlags & TRACE_WER) {
        result &= TraceClean_WERReports(Stats);
    }
    if (CategoryFlags & TRACE_SEARCH_INDEX) {
        result &= TraceClean_SearchIndex(Stats);
    }
    if (CategoryFlags & TRACE_SUPERFETCH) {
        result &= TraceClean_Superfetch(Stats);
    }
    
    if (oldValue != NULL) {
        Wow64RevertWow64FsRedirection(oldValue);
    }
    
    return result;
}

// Get statistics string
void TraceClean_GetStatsString(const CLEAN_STATS* Stats, char* buffer, size_t bufferSize) {
    _snprintf_s(buffer, bufferSize, _TRUNCATE,
                "Trace Cleaning Results:\n"
                "  Event Logs Cleared: %lu\n"
                "  Registry Keys Deleted: %lu\n"
                "  Files Deleted: %lu\n"
                "  Folders Cleaned: %lu\n"
                "  USN Entries Modified: %lu\n"
                "  Errors: %lu",
                Stats->EventLogsCleared,
                Stats->RegistryKeysDeleted,
                Stats->FilesDeleted,
                Stats->FoldersCleaned,
                Stats->UsnEntriesModified,
                Stats->Errors);
}

/*
 * Trace Cleaner - File System Module
 * Cleans Prefetch, Recent Items, Jump Lists, Temp Files, Thumbnails, Shellbags
 */

#include "tc_filesystem.h"
#include <shlobj.h>
#include <stdio.h>

// ==================== PREFETCH CLEANER ====================

BOOL TraceClean_Prefetch(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    wchar_t prefetchPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch", prefetchPath, MAX_PATH);
    
    // Stop Prefetch service if running
    StopService(L"SysMain");
    Sleep(500);
    
    // Delete all .pf files
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    _snwprintf_s(searchPath, MAX_PATH, L"%s\\*.pf", prefetchPath);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                continue;
            }
            
            wchar_t fullPath[MAX_PATH];
            _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", prefetchPath, findData.cFileName);
            
            SecureWipeFileInternal(fullPath);
            if (DeleteFileW(fullPath)) {
                Stats->FilesDeleted++;
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    // Delete ReadyBoot trace files
    wchar_t readyBootPath[MAX_PATH];
    _snwprintf_s(readyBootPath, MAX_PATH, L"%s\\ReadyBoot", prefetchPath);
    DeleteDirectoryRecursive(readyBootPath, Stats);
    
    // Clear layout.ini
    wchar_t layoutPath[MAX_PATH];
    _snwprintf_s(layoutPath, MAX_PATH, L"%s\\layout.ini", prefetchPath);
    SecureWipeFileInternal(layoutPath);
    DeleteFileW(layoutPath);
    
    Stats->FoldersCleaned++;
    
    // Restart service
    StartServiceSimple(L"SysMain");
    
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
        Stats->RegistryKeysDeleted++;
    }
    
    // Office 15.0 (2013)
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Office\\15.0\\Word\\File MRU",
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
    _snwprintf_s(autoDestPath, MAX_PATH, L"%s\\AutomaticDestinations", jumpListPath);
    DeleteDirectoryRecursive(autoDestPath, Stats);
    
    // CustomDestinations
    wchar_t customDestPath[MAX_PATH];
    _snwprintf_s(customDestPath, MAX_PATH, L"%s\\CustomDestinations", jumpListPath);
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

// ==================== THUMBNAIL CACHE CLEANER ====================

BOOL DeleteFilesByPattern(const wchar_t* dirPath, const wchar_t* pattern, CLEAN_STATS* Stats) {
    BOOL result = FALSE;
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    _snwprintf_s(searchPath, MAX_PATH, L"%s\\%s", dirPath, pattern);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        
        wchar_t fullPath[MAX_PATH];
        _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", dirPath, findData.cFileName);
        SecureWipeFileInternal(fullPath);
        if (DeleteFileW(fullPath)) {
            Stats->FilesDeleted++;
            result = TRUE;
        }
    } while (FindNextFileW(hFind, &findData));
    
    FindClose(hFind);
    return result;
}

BOOL TraceClean_Thumbnails(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Notify Explorer to refresh
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    
    // Clear thumbnail cache path
    wchar_t thumbPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer",
                              thumbPath, MAX_PATH);
    
    // Delete thumbcache files
    DeleteFilesByPattern(thumbPath, L"thumbcache_*.db", Stats);
    
    // Clear icon cache
    ClearIconCache(Stats);
    
    return result;
}

BOOL ClearIconCache(CLEAN_STATS* Stats) {
    wchar_t thumbPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer",
                              thumbPath, MAX_PATH);
    
    return DeleteFilesByPattern(thumbPath, L"iconcache_*.db", Stats);
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
    
    return result;
}

/*
 * Trace Cleaner - Search and Superfetch Module
 * Clears Windows Search index and Superfetch data
 */

#include "tc_search.h"
#include <stdio.h>

// ==================== SEARCH INDEX CLEANER ====================

BOOL StopWindowsSearch(void) {
    return StopService(L"WSearch");
}

BOOL StartWindowsSearch(void) {
    return StartServiceSimple(L"WSearch");
}

BOOL ResetSearchDatabase(void) {
    // Delete Windows Search database files
    wchar_t searchPath[MAX_PATH];
    
    // ProgramData search
    ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows",
                               searchPath, MAX_PATH);
    
    // Common database files
    const wchar_t* dbFiles[] = {
        L"Windows.edb",
        L"Windows.db",
        L"CiFiles",
        L"GatherLogs",
    };
    
    for (DWORD i = 0; i < sizeof(dbFiles) / sizeof(dbFiles[0]); i++) {
        wchar_t fullPath[MAX_PATH];
        _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", searchPath, dbFiles[i]);
        DeleteDirectoryRecursive(fullPath, NULL);
        SecureWipeFileInternal(fullPath);
        DeleteFileW(fullPath);
    }
    
    return TRUE;
}

BOOL TraceClean_SearchIndex(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Stop Windows Search service
    StopWindowsSearch();
    Sleep(2000);
    
    // Reset the database
    ResetSearchDatabase();
    
    // Also clear user-specific search data
    wchar_t userSearchPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer\\WordWheelQuery",
                               userSearchPath, MAX_PATH);
    DeleteDirectoryRecursive(userSearchPath, Stats);
    
    // Clear recent search queries
    HKEY hSearch;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentItems",
                      0, KEY_READ | KEY_WRITE, &hSearch) == ERROR_SUCCESS) {
        RegDeleteTreeW(hSearch, NULL);
        RegCloseKey(hSearch);
    }
    
    // Restart service
    StartWindowsSearch();
    
    Stats->FoldersCleaned++;
    return result;
}

// ==================== SUPERFETCH CLEANER ====================

BOOL ClearSuperfetchDatabase(void) {
    wchar_t pfPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch", pfPath, MAX_PATH);
    
    // Delete .pf files
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    _snwprintf_s(searchPath, MAX_PATH, L"%s\\*.pf", pfPath);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                wchar_t fullPath[MAX_PATH];
                _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", pfPath, findData.cFileName);
                SecureWipeFileInternal(fullPath);
                DeleteFileW(fullPath);
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    return TRUE;
}

BOOL TraceClean_Superfetch(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Stop SysMain (Superfetch)
    StopService(L"SysMain");
    Sleep(1000);
    
    // Clear Superfetch database
    ClearSuperfetchDatabase();
    
    // Clear ReadyBoot
    wchar_t readyBootPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch\\ReadyBoot", readyBootPath, MAX_PATH);
    DeleteDirectoryRecursive(readyBootPath, Stats);
    
    // Clear layout.ini
    wchar_t layoutPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch\\layout.ini", layoutPath, MAX_PATH);
    SecureWipeFileInternal(layoutPath);
    DeleteFileW(layoutPath);
    
    // Clear trace files
    wchar_t tracePath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch\\*.trace", tracePath, MAX_PATH);
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(tracePath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                wchar_t fullPath[MAX_PATH];
                ExpandEnvironmentStringsW(L"%SystemRoot%\\Prefetch", fullPath, MAX_PATH);
                _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", fullPath, findData.cFileName);
                SecureWipeFileInternal(fullPath);
                DeleteFileW(fullPath);
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    
    // Clear registry tracking
    HKEY hPrefetch;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
                      0, KEY_SET_VALUE, &hPrefetch) == ERROR_SUCCESS) {
        // Reset BootId to indicate new boot session
        DWORD bootId = 0;
        RegSetValueExW(hPrefetch, L"BootId", 0, REG_DWORD, (BYTE*)&bootId, sizeof(bootId));
        RegCloseKey(hPrefetch);
    }
    
    // Restart service
    StartServiceSimple(L"SysMain");
    
    return result;
}

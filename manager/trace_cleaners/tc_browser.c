/*
 * Trace Cleaner - Browser Module
 * Clears browser cache, cookies, and history for major browsers
 */

#include "tc_browser.h"
#include <shlobj.h>
#include <stdio.h>

// Chrome profile cleaner
BOOL CleanChrome(CLEAN_STATS* Stats) {
    BOOL result = FALSE;
    
    wchar_t chromePath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, chromePath))) {
        _snwprintf_s(chromePath, MAX_PATH, _TRUNCATE, 
                    L"%s\\Google\\Chrome\\User Data", chromePath);
        
        // Delete Cache, Cookies, History, etc.
        const wchar_t* patterns[] = {
            L"Default\\Cache",
            L"Default\\Code Cache",
            L"Default\\Cookies",
            L"Default\\History",
            L"Default\\Visited Links",
            L"Default\\Top Sites",
            L"Default\\Network Action Predictor",
            L"Default\\Shortcuts",
            L"Default\\Sessions",
            L"ShaderCache",
        };
        
        for (DWORD i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
            wchar_t fullPath[MAX_PATH];
            _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", chromePath, patterns[i]);
            DeleteDirectoryRecursive(fullPath, Stats);
        }
        
        // Also clear all profile directories
        WIN32_FIND_DATAW findData;
        HANDLE hFind;
        wchar_t profileSearch[MAX_PATH];
        _snwprintf_s(profileSearch, MAX_PATH, L"%s\\*", chromePath);
        
        hFind = FindFirstFileW(profileSearch, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (wcsncmp(findData.cFileName, L"Profile ", 8) == 0) {
                        wchar_t profilePath[MAX_PATH];
                        _snwprintf_s(profilePath, MAX_PATH, L"%s\\%s", 
                                    chromePath, findData.cFileName);
                        
                        const wchar_t* profilePatterns[] = {
                            L"Cache",
                            L"Code Cache",
                            L"Cookies",
                            L"History",
                            L"Visited Links",
                        };
                        
                        for (DWORD j = 0; j < sizeof(profilePatterns) / sizeof(profilePatterns[0]); j++) {
                            wchar_t fullPath[MAX_PATH];
                            _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", 
                                        profilePath, profilePatterns[j]);
                            DeleteDirectoryRecursive(fullPath, Stats);
                        }
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
        
        result = TRUE;
    }
    
    return result;
}

// Firefox profile cleaner
BOOL CleanFirefox(CLEAN_STATS* Stats) {
    BOOL result = FALSE;
    
    wchar_t firefoxPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, firefoxPath))) {
        _snwprintf_s(firefoxPath, MAX_PATH, _TRUNCATE,
                    L"%s\\Mozilla\\Firefox\\Profiles", firefoxPath);
        
        // Find all Firefox profiles
        WIN32_FIND_DATAW findData;
        HANDLE hFind;
        wchar_t profileSearch[MAX_PATH];
        _snwprintf_s(profileSearch, MAX_PATH, L"%s\\*.default*", firefoxPath);
        
        hFind = FindFirstFileW(profileSearch, &findData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    wchar_t profilePath[MAX_PATH];
                    _snwprintf_s(profilePath, MAX_PATH, L"%s\\%s", 
                                firefoxPath, findData.cFileName);
                    
                    const wchar_t* patterns[] = {
                        L"cache2",
                        L"startupCache",
                        L"thumbnails",
                        L"cookies.sqlite",
                        L"places.sqlite",
                        L"formhistory.sqlite",
                        L"sessionstore.jsonlz4",
                        L"sessionCheckpoints.json",
                        L"webappsstore.sqlite",
                    };
                    
                    for (DWORD i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
                        wchar_t fullPath[MAX_PATH];
                        _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", 
                                    profilePath, patterns[i]);
                        DeleteDirectoryRecursive(fullPath, Stats);
                        DeleteFileW(fullPath);
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
        
        result = TRUE;
    }
    
    return result;
}

// Edge cleaner (Chromium-based)
BOOL CleanEdge(CLEAN_STATS* Stats) {
    BOOL result = FALSE;
    
    wchar_t edgePath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, edgePath))) {
        _snwprintf_s(edgePath, MAX_PATH, _TRUNCATE,
                    L"%s\\Microsoft\\Edge\\User Data", edgePath);
        
        const wchar_t* patterns[] = {
            L"Default\\Cache",
            L"Default\\Code Cache",
            L"Default\\Cookies",
            L"Default\\History",
            L"Default\\Shortcuts",
        };
        
        for (DWORD i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
            wchar_t fullPath[MAX_PATH];
            _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", edgePath, patterns[i]);
            DeleteDirectoryRecursive(fullPath, Stats);
        }
        
        result = TRUE;
    }
    
    return result;
}

// Internet Explorer cleaner
BOOL CleanInternetExplorer(CLEAN_STATS* Stats) {
    BOOL result = FALSE;
    
    // Clear IE cache using WinInet
    HANDLE hProcess = NULL;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    // RunDll32.exe for clearing cache
    wchar_t cmdLine[] = L"RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 4351";
    
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        result = TRUE;
    }
    
    // Also clean IE temp files manually
    wchar_t iePath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, iePath))) {
        _snwprintf_s(iePath, MAX_PATH, _TRUNCATE,
                    L"%s\\Microsoft\\Windows\\INetCache\\IE", iePath);
        DeleteDirectoryRecursive(iePath, Stats);
    }
    
    return result;
}

// Main browser trace cleaner
BOOL TraceClean_BrowserTraces(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    result &= CleanChrome(Stats);
    result &= CleanFirefox(Stats);
    result &= CleanEdge(Stats);
    result &= CleanInternetExplorer(Stats);
    
    // Update stats
    Stats->BrowserCookiesDeleted++;  // Approximate
    Stats->BrowserCacheEntries++;    // Approximate
    Stats->BrowserHistoryEntries++;  // Approximate
    
    return result;
}

// Helper function to delete browser profile data
BOOL DeleteBrowserProfileData(const wchar_t* profilePath, const wchar_t** patterns, 
                              DWORD patternCount, CLEAN_STATS* Stats) {
    if (!profilePath || !patterns || patternCount == 0) return FALSE;
    
    for (DWORD i = 0; i < patternCount; i++) {
        wchar_t fullPath[MAX_PATH];
        _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", profilePath, patterns[i]);
        DeleteDirectoryRecursive(fullPath, Stats);
        DeleteFileW(fullPath);
    }
    
    return TRUE;
}

/*
 * Trace Cleaner - Main API Implementation
 * High-level API for running trace cleaning operations
 */

#include "tc_api.h"

// Include all cleaner modules
#include "tc_eventlogs.h"
#include "tc_registry.h"
#include "tc_filesystem.h"
#include "tc_usn.h"
#include "tc_browser.h"
#include "tc_wer.h"
#include "tc_search.h"
#include "tc_network.h"
#include "tc_clipboard.h"

#include <stdio.h>
#include <string.h>

// ============================================================================
// MAIN API FUNCTIONS
// ============================================================================

void TraceClean_InitConfig(CLEAN_CONFIG* Config) {
    if (!Config) return;
    
    Config->Categories = TRACE_ALL;
    Config->SecureWipe = FALSE;
    Config->BackupRegistry = FALSE;
    Config->VerboseLogging = FALSE;
    Config->StopServices = TRUE;
    Config->WipePasses = 1;
    Config->ProgressCb = NULL;
    Config->ProgressContext = NULL;
}

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
    result &= TraceClean_DnsCache(Stats);
    result &= TraceClean_ArpCache(Stats);
    result &= TraceClean_Clipboard(Stats);
    
    // Restore file system redirection
    if (oldValue != NULL) {
        Wow64RevertWow64FsRedirection(oldValue);
    }
    
    return result;
}

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
    if (CategoryFlags & TRACE_DNS_CACHE) {
        result &= TraceClean_DnsCache(Stats);
    }
    if (CategoryFlags & TRACE_ARP_CACHE) {
        result &= TraceClean_ArpCache(Stats);
    }
    if (CategoryFlags & TRACE_CLIPBOARD) {
        result &= TraceClean_Clipboard(Stats);
    }
    
    if (oldValue != NULL) {
        Wow64RevertWow64FsRedirection(oldValue);
    }
    
    return result;
}

BOOL TraceClean_RunWithConfig(const CLEAN_CONFIG* Config, CLEAN_STATS* Stats) {
    if (!Config || !Stats) return FALSE;
    
    RtlZeroMemory(Stats, sizeof(CLEAN_STATS));
    
    // Validate categories
    if (!TraceClean_ValidateCategories(Config->Categories)) {
        Stats->Errors++;
        return FALSE;
    }
    
    // Check admin rights if required
    if (TraceClean_RequiresAdmin(Config->Categories)) {
        BOOL isAdmin = FALSE;
        PSID administratorsGroup = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        
        if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                    DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                    &administratorsGroup)) {
            CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
            FreeSid(administratorsGroup);
        }
        
        if (!isAdmin) {
            Stats->Errors++;
            return FALSE;
        }
    }
    
    // Stop services if requested
    if (Config->StopServices) {
        // Stop relevant services based on categories
        if (Config->Categories & TRACE_PREFETCH) {
            StopService(L"SysMain");
        }
        if (Config->Categories & TRACE_SEARCH_INDEX) {
            StopService(L"WSearch");
        }
    }
    
    // Run cleaning
    BOOL result = TraceClean_RunCategory(Config->Categories, Stats);
    
    // Restart services
    if (Config->StopServices) {
        if (Config->Categories & TRACE_PREFETCH) {
            StartServiceSimple(L"SysMain");
        }
        if (Config->Categories & TRACE_SEARCH_INDEX) {
            StartServiceSimple(L"WSearch");
        }
    }
    
    return result;
}

BOOL TraceClean_RunPreset(TRACE_PRESET Preset, CLEAN_STATS* Stats) {
    CLEAN_CONFIG config;
    TraceClean_InitConfig(&config);
    config.Categories = (DWORD)Preset;
    
    return TraceClean_RunWithConfig(&config, Stats);
}

void TraceClean_GetStatsString(const CLEAN_STATS* Stats, char* buffer, size_t bufferSize) {
    _snprintf_s(buffer, bufferSize, _TRUNCATE,
                "Trace Cleaning Results:\n"
                "  Event Logs Cleared: %lu\n"
                "  Registry Keys Deleted: %lu\n"
                "  Files Deleted: %lu\n"
                "  Files Wiped: %lu\n"
                "  Folders Cleaned: %lu\n"
                "  USN Entries Modified: %lu\n"
                "  DNS Cache Entries: %lu\n"
                "  ARP Cache Entries: %lu\n"
                "  Errors: %lu\n"
                "  Warnings: %lu",
                Stats->EventLogsCleared,
                Stats->RegistryKeysDeleted,
                Stats->FilesDeleted,
                Stats->FilesWiped,
                Stats->FoldersCleaned,
                Stats->UsnEntriesModified,
                Stats->DnsCacheEntries,
                Stats->ArpCacheEntries,
                Stats->Errors,
                Stats->Warnings);
}

void TraceClean_GetStatsStringW(const CLEAN_STATS* Stats, wchar_t* buffer, size_t bufferSize) {
    _snwprintf_s(buffer, bufferSize, _TRUNCATE,
                L"Trace Cleaning Results:\n"
                L"  Event Logs Cleared: %lu\n"
                L"  Registry Keys Deleted: %lu\n"
                L"  Files Deleted: %lu\n"
                L"  Files Wiped: %lu\n"
                L"  Folders Cleaned: %lu\n"
                L"  USN Entries Modified: %lu\n"
                L"  DNS Cache Entries: %lu\n"
                L"  ARP Cache Entries: %lu\n"
                L"  Errors: %lu\n"
                L"  Warnings: %lu",
                Stats->EventLogsCleared,
                Stats->RegistryKeysDeleted,
                Stats->FilesDeleted,
                Stats->FilesWiped,
                Stats->FoldersCleaned,
                Stats->UsnEntriesModified,
                Stats->DnsCacheEntries,
                Stats->ArpCacheEntries,
                Stats->Errors,
                Stats->Warnings);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

const char* TraceClean_GetCategoryName(DWORD Category) {
    switch (Category) {
        case TRACE_EVENT_LOGS:    return "Event Logs";
        case TRACE_REGISTRY:      return "Registry Traces";
        case TRACE_PREFETCH:      return "Prefetch";
        case TRACE_RECENT_ITEMS:  return "Recent Items";
        case TRACE_JUMPLISTS:     return "Jump Lists";
        case TRACE_TEMP_FILES:    return "Temporary Files";
        case TRACE_USN_JOURNAL:   return "USN Journal";
        case TRACE_THUMBNAILS:    return "Thumbnail Cache";
        case TRACE_SHELLBAGS:     return "Shellbags";
        case TRACE_BROWSER:       return "Browser Traces";
        case TRACE_WER:           return "Error Reporting";
        case TRACE_SEARCH_INDEX:  return "Search Index";
        case TRACE_SUPERFETCH:    return "Superfetch";
        case TRACE_DNS_CACHE:     return "DNS Cache";
        case TRACE_ARP_CACHE:     return "ARP Cache";
        case TRACE_CLIPBOARD:     return "Clipboard History";
        default:                  return "Unknown";
    }
}

const char* TraceClean_GetCategoryDescription(DWORD Category) {
    switch (Category) {
        case TRACE_EVENT_LOGS:    return "Clear Windows Event Log channels";
        case TRACE_REGISTRY:      return "Delete UserAssist, RunMRU, and other registry traces";
        case TRACE_PREFETCH:      return "Delete Windows Prefetch files";
        case TRACE_RECENT_ITEMS:  return "Clear recent files and folders lists";
        case TRACE_JUMPLISTS:     return "Delete Jump List history";
        case TRACE_TEMP_FILES:    return "Delete temporary files and folders";
        case TRACE_USN_JOURNAL:   return "Modify USN Journal entries";
        case TRACE_THUMBNAILS:    return "Clear thumbnail cache";
        case TRACE_SHELLBAGS:     return "Delete shellbag registry entries";
        case TRACE_BROWSER:       return "Clear browser cache, cookies, and history";
        case TRACE_WER:           return "Delete Windows Error Reporting files";
        case TRACE_SEARCH_INDEX:  return "Reset Windows Search index";
        case TRACE_SUPERFETCH:    return "Clear Superfetch data";
        case TRACE_DNS_CACHE:     return "Flush DNS resolver cache";
        case TRACE_ARP_CACHE:     return "Clear ARP cache entries";
        case TRACE_CLIPBOARD:     return "Clear clipboard and clipboard history";
        default:                  return "No description available";
    }
}

DWORD TraceClean_EstimateTime(DWORD CategoryFlags) {
    DWORD seconds = 0;
    
    if (CategoryFlags & TRACE_EVENT_LOGS)    seconds += 5;
    if (CategoryFlags & TRACE_REGISTRY)      seconds += 3;
    if (CategoryFlags & TRACE_PREFETCH)      seconds += 2;
    if (CategoryFlags & TRACE_RECENT_ITEMS)  seconds += 2;
    if (CategoryFlags & TRACE_JUMPLISTS)     seconds += 2;
    if (CategoryFlags & TRACE_TEMP_FILES)    seconds += 10;
    if (CategoryFlags & TRACE_USN_JOURNAL)   seconds += 30;
    if (CategoryFlags & TRACE_THUMBNAILS)    seconds += 3;
    if (CategoryFlags & TRACE_SHELLBAGS)     seconds += 2;
    if (CategoryFlags & TRACE_BROWSER)       seconds += 5;
    if (CategoryFlags & TRACE_WER)           seconds += 3;
    if (CategoryFlags & TRACE_SEARCH_INDEX)  seconds += 10;
    if (CategoryFlags & TRACE_SUPERFETCH)    seconds += 5;
    if (CategoryFlags & TRACE_DNS_CACHE)     seconds += 1;
    if (CategoryFlags & TRACE_ARP_CACHE)     seconds += 1;
    if (CategoryFlags & TRACE_CLIPBOARD)     seconds += 1;
    
    return seconds;
}

BOOL TraceClean_RequiresAdmin(DWORD CategoryFlags) {
    // Most categories require admin, except these:
    DWORD noAdminRequired = TRACE_BROWSER | TRACE_CLIPBOARD;
    
    return (CategoryFlags & ~noAdminRequired) != 0;
}

BOOL TraceClean_ValidateCategories(DWORD CategoryFlags) {
    if (CategoryFlags == 0) return FALSE;
    if (CategoryFlags & ~TRACE_ALL) return FALSE;
    return TRUE;
}

BOOL TraceClean_CreateRegistryBackup(const wchar_t* BackupPath) {
    if (!BackupPath) return FALSE;
    (void)BackupPath;
    return TRUE;  // Placeholder
}

BOOL TraceClean_RestoreRegistryBackup(const wchar_t* BackupPath) {
    if (!BackupPath) return FALSE;
    (void)BackupPath;
    return TRUE;  // Placeholder
}

// ============================================================================
// ADVANCED FUNCTIONS
// ============================================================================

BOOL TraceClean_SecureWipeFile(const wchar_t* FilePath, DWORD Passes) {
    if (!FilePath || Passes == 0) return FALSE;
    if (Passes > 35) Passes = 35;
    
    HANDLE hFile = CreateFileW(FilePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                               FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    const DWORD bufferSize = 65536;
    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    BOOL result = TRUE;
    const BYTE patterns[] = { 0x00, 0xFF, 0x55, 0xAA, 0x92, 0x49, 0x24 };
    const DWORD numPatterns = sizeof(patterns) / sizeof(patterns[0]);
    
    for (DWORD pass = 0; pass < Passes && result; pass++) {
        BYTE pattern = (pass < numPatterns) ? patterns[pass] : (BYTE)(pass & 0xFF);
        memset(buffer, pattern, bufferSize);
        
        SetFilePointerEx(hFile, (LARGE_INTEGER){0}, NULL, FILE_BEGIN);
        
        LONGLONG remaining = fileSize.QuadPart;
        while (remaining > 0 && result) {
            DWORD toWrite = (remaining < bufferSize) ? (DWORD)remaining : bufferSize;
            DWORD written = 0;
            result = WriteFile(hFile, buffer, toWrite, &written, NULL);
            remaining -= written;
        }
        
        FlushFileBuffers(hFile);
    }
    
    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hFile);
    
    if (result) {
        result = DeleteFileW(FilePath);
    }
    
    return result;
}

BOOL TraceClean_SecureWipeDirectory(const wchar_t* DirPath, DWORD Passes, CLEAN_STATS* Stats) {
    if (!DirPath || !Stats) return FALSE;
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    _snwprintf_s(searchPath, MAX_PATH, _TRUNCATE, L"%s\\*", DirPath);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    
    BOOL result = TRUE;
    
    do {
        if (wcscmp(findData.cFileName, L".") == 0 ||
            wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        
        wchar_t fullPath[MAX_PATH];
        _snwprintf_s(fullPath, MAX_PATH, _TRUNCATE, L"%s\\%s", DirPath, findData.cFileName);
        
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            result &= TraceClean_SecureWipeDirectory(fullPath, Passes, Stats);
            RemoveDirectoryW(fullPath);
        } else {
            if (TraceClean_SecureWipeFile(fullPath, Passes)) {
                Stats->FilesWiped++;
            } else {
                Stats->Errors++;
                result = FALSE;
            }
        }
    } while (FindNextFileW(hFind, &findData));
    
    FindClose(hFind);
    return result;
}

BOOL TraceClean_GetUsnStats(UINT64* TotalEntries, UINT64* SizeOnDisk) {
    if (!TotalEntries || !SizeOnDisk) return FALSE;
    
    *TotalEntries = 0;
    *SizeOnDisk = 0;
    return TRUE;  // Placeholder - would use FSCTL_QUERY_USN_JOURNAL
}

BOOL TraceClean_CheckSafety(void) {
    return TRUE;  // Assume safe for now
}

/*
 * HWID Spoofer - Trace Cleaner Header
 * 
 * Defines for trace cleaning categories and API
 */

#ifndef TRACE_CLEANER_H
#define TRACE_CLEANER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Trace cleaning categories
typedef enum _TRACE_CATEGORY {
    TRACE_EVENT_LOGS     = 0x0001,
    TRACE_REGISTRY       = 0x0002,
    TRACE_PREFETCH       = 0x0004,
    TRACE_RECENT_ITEMS   = 0x0008,
    TRACE_JUMPLISTS      = 0x0010,
    TRACE_TEMP_FILES     = 0x0020,
    TRACE_USN_JOURNAL    = 0x0040,
    TRACE_THUMBNAILS     = 0x0080,
    TRACE_SHELLBAGS      = 0x0100,
    TRACE_BROWSER        = 0x0200,
    TRACE_WER            = 0x0400,
    TRACE_SEARCH_INDEX   = 0x0800,
    TRACE_SUPERFETCH     = 0x1000,
    TRACE_ALL            = 0xFFFF
} TRACE_CATEGORY;

// Cleaning statistics
typedef struct _CLEAN_STATS {
    DWORD EventLogsCleared;
    DWORD RegistryKeysDeleted;
    DWORD FilesDeleted;
    DWORD FoldersCleaned;
    DWORD UsnEntriesModified;
    DWORD Errors;
} CLEAN_STATS;

// Main API functions
BOOL TraceClean_RunAll(CLEAN_STATS* Stats);
BOOL TraceClean_RunCategory(DWORD CategoryFlags, CLEAN_STATS* Stats);
void TraceClean_GetStatsString(const CLEAN_STATS* Stats, char* buffer, size_t bufferSize);

// Individual cleaners (can be called separately)
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

#ifdef __cplusplus
}
#endif

#endif // TRACE_CLEANER_H

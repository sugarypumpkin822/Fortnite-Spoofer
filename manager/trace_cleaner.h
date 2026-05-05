/*
 * HWID Spoofer - Trace Cleaner Header
 * 
 * Comprehensive system trace cleaning for forensic artifact removal.
 * This module provides privacy protection by clearing system traces
 * that could be used to track system usage history.
 * 
 * FEATURES:
 * - Windows Event Log clearing
 * - Registry trace removal
 * - Prefetch data cleanup
 * - Temporary file deletion
 * - USN Journal manipulation
 * - Browser trace cleaning
 * - Windows Error Reporting cleanup
 * - Search indexer reset
 * 
 * EDUCATIONAL/DEFENSIVE USE ONLY
 * This module is intended for:
 * - Privacy protection on systems you own
 * - Forensic countermeasures research
 * - System maintenance and cleanup
 * - Security testing with proper authorization
 */

#ifndef TRACE_CLEANER_H
#define TRACE_CLEANER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// TRACE CLEANING CATEGORIES
// ============================================================================

typedef enum _TRACE_CATEGORY {
    TRACE_EVENT_LOGS     = 0x0001,   // Windows Event Logs
    TRACE_REGISTRY       = 0x0002,   // Registry traces (UserAssist, RunMRU, etc.)
    TRACE_PREFETCH       = 0x0004,   // Prefetch files
    TRACE_RECENT_ITEMS   = 0x0008,   // Recent files/folders
    TRACE_JUMPLISTS      = 0x0010,   // Jump list history
    TRACE_TEMP_FILES     = 0x0020,   // Temporary files
    TRACE_USN_JOURNAL    = 0x0040,   // USN Journal entries
    TRACE_THUMBNAILS     = 0x0080,   // Thumbnail cache
    TRACE_SHELLBAGS      = 0x0100,   // ShellBag registry entries
    TRACE_BROWSER        = 0x0200,   // Browser traces
    TRACE_WER            = 0x0400,   // Windows Error Reporting
    TRACE_SEARCH_INDEX   = 0x0800,   // Windows Search index
    TRACE_SUPERFETCH     = 0x1000,   // Superfetch data
    TRACE_DNS_CACHE      = 0x2000,   // DNS cache
    TRACE_ARP_CACHE      = 0x4000,   // ARP cache
    TRACE_CLIPBOARD      = 0x8000,   // Clipboard history
    TRACE_ALL            = 0xFFFF    // All categories
} TRACE_CATEGORY;

// Quick preset combinations
typedef enum _TRACE_PRESET {
    PRESET_QUICK    = TRACE_EVENT_LOGS | TRACE_TEMP_FILES | TRACE_DNS_CACHE,
    PRESET_STANDARD = TRACE_EVENT_LOGS | TRACE_REGISTRY | TRACE_PREFETCH | 
                      TRACE_TEMP_FILES | TRACE_THUMBNAILS | TRACE_DNS_CACHE,
    PRESET_THOROUGH = TRACE_ALL & ~TRACE_USN_JOURNAL,  // Exclude USN for speed
    PRESET_PARANOID = TRACE_ALL  // Everything including USN
} TRACE_PRESET;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Detailed cleaning statistics
typedef struct _CLEAN_STATS {
    // Event logs
    DWORD EventLogsCleared;
    DWORD EventChannelsCleared;
    
    // Registry
    DWORD RegistryKeysDeleted;
    DWORD RegistryValuesDeleted;
    
    // File system
    DWORD FilesDeleted;
    DWORD FilesWiped;
    DWORD FoldersCleaned;
    DWORD BytesReclaimed;
    
    // USN Journal
    DWORD UsnEntriesModified;
    DWORD UsnEntriesDeleted;
    
    // Browser data
    DWORD BrowserCookiesDeleted;
    DWORD BrowserCacheEntries;
    DWORD BrowserHistoryEntries;
    
    // Network
    DWORD DnsCacheEntries;
    DWORD ArpCacheEntries;
    
    // Errors
    DWORD Errors;
    DWORD Warnings;
    
    // Timing
    DWORD DurationMs;
} CLEAN_STATS;

// Progress callback for long operations
typedef void (*TRACE_CLEAN_PROGRESS_CB)(DWORD Category, DWORD PercentComplete, 
                                         const wchar_t* CurrentOperation, void* UserContext);

// Configuration options
typedef struct _CLEAN_CONFIG {
    DWORD Categories;              // Categories to clean (TRACE_CATEGORY flags)
    BOOL  SecureWipe;              // Use secure file wiping (slower but safer)
    BOOL  BackupRegistry;          // Create registry backup before deletion
    BOOL  VerboseLogging;          // Enable detailed logging
    BOOL  StopServices;            // Stop relevant services before cleaning
    DWORD WipePasses;              // Number of wipe passes (1-35, 0 = single pass)
    TRACE_CLEAN_PROGRESS_CB ProgressCb;  // Progress callback
    void* ProgressContext;         // User context for callback
} CLEAN_CONFIG;

// Main API functions
BOOL TraceClean_RunAll(CLEAN_STATS* Stats);
BOOL TraceClean_RunCategory(DWORD CategoryFlags, CLEAN_STATS* Stats);
void TraceClean_GetStatsString(const CLEAN_STATS* Stats, char* buffer, size_t bufferSize);

// Run cleaning with configuration options
BOOL TraceClean_RunWithConfig(const CLEAN_CONFIG* Config, CLEAN_STATS* Stats);

// Quick clean with preset
BOOL TraceClean_RunPreset(TRACE_PRESET Preset, CLEAN_STATS* Stats);

// Get statistics as wide string
void TraceClean_GetStatsStringW(const CLEAN_STATS* Stats, wchar_t* buffer, size_t bufferSize);

// Initialize configuration with defaults
void TraceClean_InitConfig(CLEAN_CONFIG* Config);

// ============================================================================
// INDIVIDUAL CLEANERS (can be called separately)
// ============================================================================

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
BOOL TraceClean_DnsCache(CLEAN_STATS* Stats);
BOOL TraceClean_ArpCache(CLEAN_STATS* Stats);
BOOL TraceClean_Clipboard(CLEAN_STATS* Stats);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Get category name
const char* TraceClean_GetCategoryName(DWORD Category);

// Get category description
const char* TraceClean_GetCategoryDescription(DWORD Category);

// Estimate time required for cleaning (in seconds)
DWORD TraceClean_EstimateTime(DWORD CategoryFlags);

// Check if admin rights are required for categories
BOOL TraceClean_RequiresAdmin(DWORD CategoryFlags);

// Validate categories (returns FALSE if invalid combination)
BOOL TraceClean_ValidateCategories(DWORD CategoryFlags);

// Create registry backup before cleaning
BOOL TraceClean_CreateRegistryBackup(const wchar_t* BackupPath);

// Restore registry from backup
BOOL TraceClean_RestoreRegistryBackup(const wchar_t* BackupPath);

// ============================================================================
// ADVANCED FUNCTIONS
// ============================================================================

// Secure file wipe with multiple passes
BOOL TraceClean_SecureWipeFile(const wchar_t* FilePath, DWORD Passes);

// Secure wipe directory contents
BOOL TraceClean_SecureWipeDirectory(const wchar_t* DirPath, DWORD Passes, CLEAN_STATS* Stats);

// Get USN journal statistics before cleaning
BOOL TraceClean_GetUsnStats(UINT64* TotalEntries, UINT64* SizeOnDisk);

// Check cleaning safety (are critical files protected?)
BOOL TraceClean_CheckSafety(void);

#ifdef __cplusplus
}
#endif

#endif // TRACE_CLEANER_H

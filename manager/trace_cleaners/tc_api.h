/*
 * Trace Cleaner - Main API Header
 * High-level API for running trace cleaning operations
 */

#ifndef TC_API_H
#define TC_API_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// MAIN API FUNCTIONS
// ============================================================================

// Run all trace cleaning operations
BOOL TraceClean_RunAll(CLEAN_STATS* Stats);

// Run selective trace cleaning based on category flags
BOOL TraceClean_RunCategory(DWORD CategoryFlags, CLEAN_STATS* Stats);

// Run cleaning with configuration options
BOOL TraceClean_RunWithConfig(const CLEAN_CONFIG* Config, CLEAN_STATS* Stats);

// Quick clean with preset
BOOL TraceClean_RunPreset(TRACE_PRESET Preset, CLEAN_STATS* Stats);

// Get statistics as formatted string
void TraceClean_GetStatsString(const CLEAN_STATS* Stats, char* buffer, size_t bufferSize);

// Get statistics as wide string
void TraceClean_GetStatsStringW(const CLEAN_STATS* Stats, wchar_t* buffer, size_t bufferSize);

// Initialize configuration with defaults
void TraceClean_InitConfig(CLEAN_CONFIG* Config);

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

// Check cleaning safety
BOOL TraceClean_CheckSafety(void);

#ifdef __cplusplus
}
#endif

#endif // TC_API_H

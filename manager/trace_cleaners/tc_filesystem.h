/*
 * Trace Cleaner - File System Module
 * Cleans Prefetch, Recent Items, Jump Lists, Temp Files, Thumbnails, Shellbags
 */

#ifndef TC_FILESYSTEM_H
#define TC_FILESYSTEM_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Prefetch cleaner
BOOL TraceClean_Prefetch(CLEAN_STATS* Stats);

// Recent Items cleaner
BOOL TraceClean_RecentItems(CLEAN_STATS* Stats);

// Jump Lists cleaner  
BOOL TraceClean_JumpLists(CLEAN_STATS* Stats);

// Temp Files cleaner
BOOL TraceClean_TempFiles(CLEAN_STATS* Stats);

// Thumbnail cache cleaner
BOOL TraceClean_Thumbnails(CLEAN_STATS* Stats);

// Shellbags cleaner
BOOL TraceClean_Shellbags(CLEAN_STATS* Stats);

// Delete files matching pattern in directory
BOOL DeleteFilesByPattern(const wchar_t* dirPath, const wchar_t* pattern, CLEAN_STATS* Stats);

// Clear icon cache
BOOL ClearIconCache(CLEAN_STATS* Stats);

#ifdef __cplusplus
}
#endif

#endif // TC_FILESYSTEM_H

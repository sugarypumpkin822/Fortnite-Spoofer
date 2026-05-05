/*
 * Trace Cleaner - Search and Superfetch Module
 * Clears Windows Search index and Superfetch data
 */

#ifndef TC_SEARCH_H
#define TC_SEARCH_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Clean Windows Search index
BOOL TraceClean_SearchIndex(CLEAN_STATS* Stats);

// Clean Superfetch/SysMain data
BOOL TraceClean_Superfetch(CLEAN_STATS* Stats);

// Stop Windows Search service
BOOL StopWindowsSearch(void);

// Start Windows Search service
BOOL StartWindowsSearch(void);

// Reset search index database
BOOL ResetSearchDatabase(void);

// Clear Superfetch database
BOOL ClearSuperfetchDatabase(void);

#ifdef __cplusplus
}
#endif

#endif // TC_SEARCH_H

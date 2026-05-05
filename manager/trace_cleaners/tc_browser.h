/*
 * Trace Cleaner - Browser Module
 * Clears browser cache, cookies, and history for major browsers
 */

#ifndef TC_BROWSER_H
#define TC_BROWSER_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Clean browser traces for all browsers
BOOL TraceClean_BrowserTraces(CLEAN_STATS* Stats);

// Chrome cleaner
BOOL CleanChrome(CLEAN_STATS* Stats);

// Firefox cleaner
BOOL CleanFirefox(CLEAN_STATS* Stats);

// Edge cleaner
BOOL CleanEdge(CLEAN_STATS* Stats);

// Internet Explorer cleaner
BOOL CleanInternetExplorer(CLEAN_STATS* Stats);

// Delete browser data by profile path
BOOL DeleteBrowserProfileData(const wchar_t* profilePath, const wchar_t** patterns, 
                              DWORD patternCount, CLEAN_STATS* Stats);

#ifdef __cplusplus
}
#endif

#endif // TC_BROWSER_H

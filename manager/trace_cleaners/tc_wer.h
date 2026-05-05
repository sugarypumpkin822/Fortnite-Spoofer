/*
 * Trace Cleaner - Windows Error Reporting Module
 * Clears WER reports and crash dumps
 */

#ifndef TC_WER_H
#define TC_WER_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Clean WER reports
BOOL TraceClean_WERReports(CLEAN_STATS* Stats);

// Clean system crash dumps
BOOL CleanSystemCrashDumps(CLEAN_STATS* Stats);

// Clean user crash dumps
BOOL CleanUserCrashDumps(CLEAN_STATS* Stats);

// Get WER report count
DWORD GetWERReportCount(void);

#ifdef __cplusplus
}
#endif

#endif // TC_WER_H

/*
 * Trace Cleaner - USN Journal Module
 * Manipulates NTFS USN Journal for file system privacy
 */

#ifndef TC_USN_H
#define TC_USN_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Clean USN Journal
BOOL TraceClean_UsnJournal(CLEAN_STATS* Stats);

// Get USN journal statistics
BOOL GetUsnJournalStats(const wchar_t* volumePath, UINT64* totalEntries, UINT64* sizeOnDisk);

// Delete USN journal on a specific volume
BOOL DeleteUsnJournalOnVolume(const wchar_t* volumePath);

// Create new USN journal on a specific volume
BOOL CreateUsnJournalOnVolume(const wchar_t* volumePath, UINT64 maxSize, UINT64 allocationDelta);

#ifdef __cplusplus
}
#endif

#endif // TC_USN_H

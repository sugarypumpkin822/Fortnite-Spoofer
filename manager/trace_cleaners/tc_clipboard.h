/*
 * Trace Cleaner - Clipboard Module
 * Clears clipboard and clipboard history
 */

#ifndef TC_CLIPBOARD_H
#define TC_CLIPBOARD_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Clean clipboard and clipboard history
BOOL TraceClean_Clipboard(CLEAN_STATS* Stats);

// Empty clipboard
BOOL EmptyClipboardData(void);

// Clear Windows 10+ clipboard history
BOOL ClearClipboardHistory(void);

#ifdef __cplusplus
}
#endif

#endif // TC_CLIPBOARD_H

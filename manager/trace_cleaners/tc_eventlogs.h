/*
 * Trace Cleaner - Event Logs Module
 * Clears Windows Event Log channels and files
 */

#ifndef TC_EVENTLOGS_H
#define TC_EVENTLOGS_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Clear Windows Event Logs
BOOL TraceClean_EventLogs(CLEAN_STATS* Stats);

// Clear a specific event log channel
BOOL ClearEventLogChannel(const wchar_t* channelName);

// Get list of event log channels
BOOL EnumerateEventLogChannels(void (*callback)(const wchar_t* channel, void* user), void* user);

#ifdef __cplusplus
}
#endif

#endif // TC_EVENTLOGS_H

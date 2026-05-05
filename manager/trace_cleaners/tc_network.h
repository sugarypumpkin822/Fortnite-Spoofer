/*
 * Trace Cleaner - Network Module
 * Clears DNS cache and ARP cache
 */

#ifndef TC_NETWORK_H
#define TC_NETWORK_H

#include "tc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Clean DNS cache
BOOL TraceClean_DnsCache(CLEAN_STATS* Stats);

// Clean ARP cache
BOOL TraceClean_ArpCache(CLEAN_STATS* Stats);

// Flush DNS using ipconfig
BOOL FlushDNSCache(void);

// Clear ARP table using netsh
BOOL ClearARPCache(void);

// Get DNS cache entry count (estimate)
DWORD GetDNSCacheEntryCount(void);

// Get ARP table entry count
DWORD GetARPEntryCount(void);

#ifdef __cplusplus
}
#endif

#endif // TC_NETWORK_H

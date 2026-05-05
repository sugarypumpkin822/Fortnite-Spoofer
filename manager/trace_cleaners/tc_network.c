/*
 * Trace Cleaner - Network Module
 * Clears DNS cache and ARP cache
 */

#include "tc_network.h"
#include <stdio.h>

// ==================== DNS CACHE CLEANER ====================

BOOL FlushDNSCache(void) {
    // Use ipconfig /flushdns
    HANDLE hProcess = NULL;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    wchar_t cmdLine[] = L"ipconfig /flushdns";
    
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        
        DWORD exitCode = 0;
        BOOL result = GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode == 0;
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return result;
    }
    
    return FALSE;
}

DWORD GetDNSCacheEntryCount(void) {
    // This would require DnsGetCacheDataTable API
    // For now, return 1 to indicate the operation was attempted
    return 1;
}

BOOL TraceClean_DnsCache(CLEAN_STATS* Stats) {
    BOOL result = FlushDNSCache();
    
    if (result) {
        Stats->DnsCacheEntries = GetDNSCacheEntryCount();
    } else {
        Stats->Errors++;
    }
    
    return result;
}

// ==================== ARP CACHE CLEANER ====================

BOOL ClearARPCache(void) {
    HANDLE hProcess = NULL;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    wchar_t cmdLine[] = L"netsh interface ip delete arpcache";
    
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        
        DWORD exitCode = 0;
        BOOL result = GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode == 0;
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return result;
    }
    
    return FALSE;
}

DWORD GetARPEntryCount(void) {
    // This would require parsing the ARP table
    // For now, return 1 to indicate the operation was attempted
    return 1;
}

BOOL TraceClean_ArpCache(CLEAN_STATS* Stats) {
    BOOL result = ClearARPCache();
    
    if (result) {
        Stats->ArpCacheEntries = GetARPEntryCount();
    } else {
        Stats->Errors++;
    }
    
    return result;
}

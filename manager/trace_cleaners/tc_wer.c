/*
 * Trace Cleaner - Windows Error Reporting Module
 * Clears WER reports and crash dumps
 */

#include "tc_wer.h"
#include <stdio.h>
#include <werapi.h>

#pragma comment(lib, "wer.lib")

// ==================== WER REPORTS CLEANER ====================

BOOL CleanSystemCrashDumps(CLEAN_STATS* Stats) {
    wchar_t dumpPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\Minidump", dumpPath, MAX_PATH);
    DeleteDirectoryRecursive(dumpPath, Stats);
    
    ExpandEnvironmentStringsW(L"%SystemRoot%\\MEMORY.DMP", dumpPath, MAX_PATH);
    SecureWipeFileInternal(dumpPath);
    DeleteFileW(dumpPath);
    
    return TRUE;
}

BOOL CleanUserCrashDumps(CLEAN_STATS* Stats) {
    wchar_t dumpPath[MAX_PATH];
    
    // Local app data crash dumps
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\CrashDumps", dumpPath, MAX_PATH);
    DeleteDirectoryRecursive(dumpPath, Stats);
    
    // WER report queue
    ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue",
                               dumpPath, MAX_PATH);
    DeleteDirectoryRecursive(dumpPath, Stats);
    
    // WER report archive
    ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive",
                               dumpPath, MAX_PATH);
    DeleteDirectoryRecursive(dumpPath, Stats);
    
    // Local WER
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Microsoft\\Windows\\WER",
                               dumpPath, MAX_PATH);
    DeleteDirectoryRecursive(dumpPath, Stats);
    
    return TRUE;
}

DWORD GetWERReportCount(void) {
    // This would use WerReportEnumerate in a full implementation
    // For now, return 0 as we can't easily enumerate without more complex code
    return 0;
}

BOOL TraceClean_WERReports(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Clean file-based WER reports
    // Note: WER queue enumeration requires undocumented APIs
    // We focus on cleaning the file-based reports which is effective
    CleanSystemCrashDumps(Stats);
    CleanUserCrashDumps(Stats);
    
    // Clear report store
    wchar_t reportStorePath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Windows\\WER\\ERC",
                               reportStorePath, MAX_PATH);
    DeleteDirectoryRecursive(reportStorePath, Stats);
    
    return result;
}

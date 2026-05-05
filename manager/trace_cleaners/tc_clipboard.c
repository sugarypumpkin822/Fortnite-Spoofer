/*
 * Trace Cleaner - Clipboard Module
 * Clears clipboard and clipboard history
 */

#include "tc_clipboard.h"

// ==================== CLIPBOARD CLEANER ====================

BOOL EmptyClipboardData(void) {
    if (!OpenClipboard(NULL)) return FALSE;
    
    BOOL result = EmptyClipboard();
    CloseClipboard();
    
    return result;
}

BOOL ClearClipboardHistory(void) {
    // For Windows 10+, clipboard history is stored in a separate process
    // We can clear it by using the echo off | clip command
    HANDLE hProcess = NULL;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    wchar_t cmdLine[] = L"cmd /c echo off | clip";
    
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return TRUE;
    }
    
    return FALSE;
}

BOOL TraceClean_Clipboard(CLEAN_STATS* Stats) {
    BOOL result = EmptyClipboardData();
    
    // Also try to clear clipboard history (Windows 10+)
    ClearClipboardHistory();
    
    if (!result) {
        Stats->Errors++;
    }
    
    return result;
}

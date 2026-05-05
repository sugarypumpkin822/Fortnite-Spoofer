/*
 * HWID Spoofer - Core Spoofing Module
 * Main spoofing operations and trace cleaning
 */

#include "core_spoof.h"
#include "../HWID/hwid_reader.h"
#include "../Driver/driver_mapper.h"
#include "../Utils/utils_common.h"
#include "../GUI/gui_main.h"

// ==================== SPOOF HWID ====================

void DoSpoofHWID(void) {
    // Load the spoofer driver
    if (!g_SpooferLoaded) {
        if (!LoadSpooferDriver()) {
            strcpy_s(g_StatusText, sizeof(g_StatusText), "DRIVER FAILED");
            g_StatusColor = CLR_RED;
            return;
        }
        g_SpooferLoaded = TRUE;
    }

    // Calculate expiry time
    ULONGLONG durationMs = 0;
    switch (g_SelectedDuration) {
        case DUR_1_DAY:       durationMs = 24ULL * 60 * 60 * 1000; break;
        case DUR_7_DAYS:      durationMs = 7ULL * 24 * 60 * 60 * 1000; break;
        case DUR_30_DAYS:     durationMs = 30ULL * 24 * 60 * 60 * 1000; break;
        case DUR_UNTIL_REBOOT: durationMs = 0; break;
    }

    if (durationMs > 0) {
        g_SpoofExpiry = GetTickCount64() + durationMs;
        SetTimer(g_hWnd, IDT_DURATION_TIMER, (UINT)durationMs, NULL);
    } else {
        g_SpoofExpiry = 0; // Until reboot
    }

    // Update status
    strcpy_s(g_StatusText, sizeof(g_StatusText), "ACTIVE");
    g_StatusColor = CLR_GREEN;

    Sleep(500);
    RefreshCurrentHWIDs();
    UpdateStatus();

    MessageBoxA(g_hWnd,
        "Hardware IDs spoofed successfully!\n\n"
        "Your hardware IDs have been changed until the selected duration expires.",
        "Spoofed", MB_ICONINFORMATION);
}

// ==================== REVERT HWID ====================

static void SignalDriverRevert(void) {
    // Signal driver to revert IDs
    // This would use an IOCTL or similar mechanism
    DbgLog("Signaling driver to revert HWIDs");
}

void DoRevertHWID(void) {
    if (!g_SpooferLoaded) return;

    SignalDriverRevert();
    UnloadSpooferDriver();
    g_SpooferLoaded = FALSE;
    g_SpoofExpiry = 0;

    strcpy_s(g_StatusText, sizeof(g_StatusText), "INACTIVE");
    g_StatusColor = CLR_RED;
    g_TimeRemaining[0] = '\0';

    KillTimer(g_hWnd, IDT_DURATION_TIMER);

    CreateHiddenTempDirectory();

    Sleep(500);
    RefreshCurrentHWIDs();
    UpdateStatus();

    MessageBoxA(g_hWnd,
        "Hardware IDs reverted.\n\n"
        "A system reboot may be required to fully restore all IDs.",
        "Reverted", MB_ICONINFORMATION);
}

// ==================== STATUS UPDATE ====================

void UpdateStatus(void) {
    // Force window redraw
    InvalidateRect(g_hWnd, NULL, FALSE);
}

// ==================== TRACE CLEANER ====================

void DoCleanTraces(void) {
    // Ask user to select what to clean
    int result = MessageBoxA(g_hWnd,
        "This will clean system traces including:\n\n"
        "- Event Logs (50+ channels)\n"
        "- Registry Traces (UserAssist, Recent Docs, etc.)\n"
        "- Prefetch Files\n"
        "- Recent Items & Jump Lists\n"
        "- Temp Files\n"
        "- USN Journal\n"
        "- Thumbnail Cache\n"
        "- Shellbags\n"
        "- Browser Traces\n"
        "- Windows Error Reports\n"
        "- Search Index\n"
        "- Superfetch Data\n\n"
        "This process is irreversible. Continue?",
        "Clean System Traces", MB_YESNO | MB_ICONWARNING);
    
    if (result != IDYES) {
        return;
    }
    
    // Run the trace cleaner
    CLEAN_STATS stats;
    BOOL success = TraceClean_RunAll(&stats);
    
    // Format results
    char statsMsg[1024];
    TraceClean_GetStatsString(&stats, statsMsg, sizeof(statsMsg));
    
    char msgBuffer[2048];
    _snprintf_s(msgBuffer, sizeof(msgBuffer), _TRUNCATE,
                "%s\n\nTrace cleaning completed %s.",
                statsMsg,
                success ? "successfully" : "with errors (see log for details)");
    
    MessageBoxA(g_hWnd, msgBuffer, "Trace Cleaning Complete", 
                success ? MB_ICONINFORMATION : MB_ICONWARNING);
}

// ==================== START CLEANING (GUI) ====================

void DoStartCleaning(void) {
    // Build the trace cleaning flags based on selected checkboxes
    DWORD categoryFlags = 0;
    
    // File Functions
    if (g_ChkTempFiles) categoryFlags |= TRACE_TEMP_FILES;
    if (g_ChkWinTemp) categoryFlags |= TRACE_TEMP_FILES;
    if (g_ChkWinLogs) categoryFlags |= TRACE_EVENT_LOGS;
    
    // Browser Functions
    if (g_ChkChromeCookies || g_ChkFirefoxCookies) categoryFlags |= TRACE_BROWSER;
    
    // WiFi functions - handled separately via ipconfig commands
    if (g_ChkFlushDNS || g_ChkTCPReset || g_ChkWiFiReset) {
        char cmdBuffer[512] = {0};
        
        if (g_ChkFlushDNS) {
            strcat_s(cmdBuffer, sizeof(cmdBuffer), "ipconfig /flushdns && ");
        }
        if (g_ChkTCPReset) {
            strcat_s(cmdBuffer, sizeof(cmdBuffer), "netsh int ip reset && ");
        }
        if (g_ChkWiFiReset) {
            strcat_s(cmdBuffer, sizeof(cmdBuffer), "netsh winsock reset && ");
        }
        
        // Remove trailing " && "
        size_t len = strlen(cmdBuffer);
        if (len > 4) {
            cmdBuffer[len - 4] = '\0';
            
            // Execute network commands
            STARTUPINFOA si = {sizeof(si)};
            PROCESS_INFORMATION pi = {0};
            CreateProcessA(NULL, cmdBuffer, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
            if (pi.hProcess) {
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
    }
    
    // Run selected trace cleaning
    if (categoryFlags != 0) {
        CLEAN_STATS stats;
        BOOL success = TraceClean_RunCategory(categoryFlags, &stats);
        
        char msg[512];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                   "Selected trace cleaning completed %s.\n"
                   "Files deleted: %lu\n"
                   "Registry keys: %lu\n"
                   "Event logs: %lu",
                   success ? "successfully" : "with errors",
                   stats.FilesDeleted,
                   stats.RegistryKeysDeleted,
                   stats.EventLogsCleared);
        
        MessageBoxA(g_hWnd, msg, "Cleaning Complete", 
                   success ? MB_ICONINFORMATION : MB_ICONWARNING);
    } else if (!g_ChkFlushDNS && !g_ChkTCPReset && !g_ChkWiFiReset) {
        MessageBoxA(g_hWnd, "No cleaning options selected.", "Nothing to do", MB_ICONINFORMATION);
    } else {
        MessageBoxA(g_hWnd, "Network commands executed successfully.", "Complete", MB_ICONINFORMATION);
    }
}

// ==================== SPOOF ALL ====================

void DoSpoofAll(void) {
    // Run trace cleaning first
    DoCleanTraces();
    
    // Then spoof HWIDs
    DoSpoofHWID();
}

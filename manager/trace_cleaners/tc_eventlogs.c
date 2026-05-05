/*
 * Trace Cleaner - Event Logs Module
 * Clears Windows Event Log channels and files
 */

#include "tc_eventlogs.h"
#include <winevt.h>
#include <stdio.h>

#pragma comment(lib, "wevtapi.lib")

// Standard event log channels to clear
static const wchar_t* g_EventChannels[] = {
    L"Application",
    L"System",
    L"Security",
    L"Setup",
    L"ForwardedEvents",
    L"HardwareEvents",
    L"Microsoft-Windows-PowerShell/Operational",
    L"Microsoft-Windows-Sysmon/Operational",
    L"Microsoft-Windows-TaskScheduler/Operational",
    L"Microsoft-Windows-Windows Defender/Operational",
    L"Microsoft-Windows-Windows Update/Operational",
    L"Microsoft-Windows-Application-Experience/Program-Inventory",
    L"Microsoft-Windows-Application-Experience/Program-Telemetry",
    L"Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
    L"Microsoft-Windows-CodeIntegrity/Operational",
    L"Microsoft-Windows-DeviceGuard/Operational",
    L"Microsoft-Windows-Security-Mitigations/KernelMode",
    L"Microsoft-Windows-Security-Mitigations/UserMode",
    L"Microsoft-Windows-Storage-Storport/Operational",
    L"Microsoft-Windows-TPM/Operational",
    L"Microsoft-Windows-AppLocker/EXE and DLL",
    L"Microsoft-Windows-AppLocker/MSI and Script",
    L"Microsoft-Windows-AppLocker/Packaged app-Execution",
    L"Microsoft-Windows-AppLocker/Packaged app-Deployment",
    L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    L"Microsoft-Windows-NetworkProfile/Operational",
    L"Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    L"Microsoft-Windows-Bits-Client/Operational",
    L"Microsoft-Windows-Bits-Client/Analytic",
    L"Microsoft-Windows-Dhcp-Client/Admin",
    L"Microsoft-Windows-Dhcp-Client/Operational",
    L"Microsoft-Windows-DNS-Client/Operational",
    L"Microsoft-Windows-GroupPolicy/Operational",
    L"Microsoft-Windows-Kernel-Boot/Operational",
    L"Microsoft-Windows-Kernel-PnP/Operational",
    L"Microsoft-Windows-Kernel-ShimEngine/Operational",
    L"Microsoft-Windows-User Profile Service/Operational",
    L"Microsoft-Windows-Windows Defender/WHC",
    L"Setup",
    L"Windows PowerShell"
};

BOOL ClearEventLogChannel(const wchar_t* channelName) {
    if (!channelName) return FALSE;
    
    // Try EvtClearLog first
    if (EvtClearLog(NULL, channelName, NULL, 0)) {
        return TRUE;
    }
    
    // Fallback to wevtutil command
    wchar_t cmdLine[512];
    _snwprintf_s(cmdLine, sizeof(cmdLine) / sizeof(wchar_t),
                512, L"wevtutil cl \"%s\" 2>nul", channelName);
    return (_wsystem(cmdLine) == 0);
}

BOOL TraceClean_EventLogs(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    DWORD channelCount = sizeof(g_EventChannels) / sizeof(g_EventChannels[0]);
    
    for (DWORD i = 0; i < channelCount; i++) {
        // Try EvtClearLog
        EVT_HANDLE hChannel = EvtOpenChannelEnum(NULL, NULL);
        if (hChannel) {
            EvtClose(hChannel);
        }
        
        if (EvtClearLog(NULL, g_EventChannels[i], NULL, 0)) {
            Stats->EventLogsCleared++;
        }
        
        // Also try wevtutil as backup
        wchar_t cmdLine[512];
        _snwprintf_s(cmdLine, 512, 
                   L"wevtutil cl \"%s\" 2>nul", g_EventChannels[i]);
        _wsystem(cmdLine);
    }
    
    // Clear Event Log files directly (backup approach)
    wchar_t eventLogPath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\winevt\\Logs", 
                               eventLogPath, MAX_PATH);
    
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];
    _snwprintf_s(searchPath, MAX_PATH, L"%s\\*.evtx", eventLogPath);
    
    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        // Stop Event Log service temporarily
        SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (hScm) {
            SC_HANDLE hService = OpenServiceW(hScm, L"EventLog", 
                                              SERVICE_STOP | SERVICE_START);
            if (hService) {
                SERVICE_STATUS status;
                ControlService(hService, SERVICE_CONTROL_STOP, &status);
                Sleep(500);
                
                do {
                    // Delete or truncate the log file
                    wchar_t fullPath[MAX_PATH];
                    _snwprintf_s(fullPath, MAX_PATH, L"%s\\%s", 
                                eventLogPath, findData.cFileName);
                    
                    HANDLE hFile = CreateFileW(fullPath, GENERIC_WRITE, 
                                              FILE_SHARE_READ, NULL,
                                              TRUNCATE_EXISTING, 
                                              FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        // Write minimal valid EVTX header
                        BYTE evtxHeader[4096] = {0};
                        evtxHeader[0] = 0x45; // 'E'
                        evtxHeader[1] = 0x6C; // 'l'
                        evtxHeader[2] = 0x66; // 'f'
                        evtxHeader[3] = 0x46; // 'F'
                        evtxHeader[4] = 0x69; // 'i'
                        evtxHeader[5] = 0x6C; // 'l'
                        evtxHeader[6] = 0x65; // 'e'
                        evtxHeader[7] = 0x00;
                        
                        DWORD written;
                        WriteFile(hFile, evtxHeader, 4096, &written, NULL);
                        CloseHandle(hFile);
                        Stats->EventLogsCleared++;
                    }
                } while (FindNextFileW(hFind, &findData));
                
                // Restart service
                StartService(hService, 0, NULL);
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hScm);
        }
        FindClose(hFind);
    }
    
    return result;
}

BOOL EnumerateEventLogChannels(void (*callback)(const wchar_t* channel, void* user), 
                               void* user) {
    if (!callback) return FALSE;
    
    EVT_HANDLE hEnum = EvtOpenChannelEnum(NULL, NULL);
    if (!hEnum) return FALSE;
    
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    LPWSTR channelPath = NULL;
    BOOL result = FALSE;
    
    while (TRUE) {
        if (!EvtNextChannelPath(hEnum, bufferSize, channelPath, &bufferUsed)) {
            DWORD error = GetLastError();
            if (error == ERROR_INSUFFICIENT_BUFFER) {
                bufferSize = bufferUsed;
                channelPath = (LPWSTR)realloc(channelPath, bufferSize * sizeof(WCHAR));
                if (!channelPath) break;
                continue;
            } else if (error == ERROR_NO_MORE_ITEMS) {
                result = TRUE;
            }
            break;
        }
        
        callback(channelPath, user);
    }
    
    if (channelPath) free(channelPath);
    EvtClose(hEnum);
    return result;
}

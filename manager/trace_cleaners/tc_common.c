/*
 * Trace Cleaners - Common Functions Implementation
 * Shared utility functions for all trace cleaners
 */

#include "tc_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ==================== SECURE FILE WIPE ====================

void SecureWipeFileInternal(const wchar_t* path) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        DeleteFileW(path);
        return;
    }

    // Allocate buffer for wiping
    const DWORD bufferSize = 65536;
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) {
        CloseHandle(hFile);
        return;
    }

    // Pattern 1: Zeros
    memset(buffer, 0, bufferSize);
    SetFilePointerEx(hFile, (LARGE_INTEGER){0}, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    for (LONGLONG written = 0; written < fileSize.QuadPart; written += bufferSize) {
        DWORD toWrite = (DWORD)((fileSize.QuadPart - written < bufferSize) ? 
                        (fileSize.QuadPart - written) : bufferSize);
        WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
    }
    FlushFileBuffers(hFile);

    // Pattern 2: Ones
    memset(buffer, 0xFF, bufferSize);
    SetFilePointerEx(hFile, (LARGE_INTEGER){0}, NULL, FILE_BEGIN);
    for (LONGLONG written = 0; written < fileSize.QuadPart; written += bufferSize) {
        DWORD toWrite = (DWORD)((fileSize.QuadPart - written < bufferSize) ? 
                        (fileSize.QuadPart - written) : bufferSize);
        WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
    }
    FlushFileBuffers(hFile);

    // Pattern 3: Random
    for (DWORD i = 0; i < bufferSize; i++) {
        buffer[i] = (BYTE)(rand() % 256);
    }
    SetFilePointerEx(hFile, (LARGE_INTEGER){0}, NULL, FILE_BEGIN);
    for (LONGLONG written = 0; written < fileSize.QuadPart; written += bufferSize) {
        DWORD toWrite = (DWORD)((fileSize.QuadPart - written < bufferSize) ? 
                        (fileSize.QuadPart - written) : bufferSize);
        WriteFile(hFile, buffer, toWrite, &bytesWritten, NULL);
    }
    FlushFileBuffers(hFile);

    free(buffer);
    CloseHandle(hFile);

    // Finally delete the file
    DeleteFileW(path);
}

// ==================== DIRECTORY OPERATIONS ====================

BOOL DeleteDirectoryRecursive(const wchar_t* path, CLEAN_STATS* Stats) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind;
    wchar_t searchPath[MAX_PATH];

    _snwprintf_s(searchPath, MAX_PATH, _TRUNCATE, L"%s\\*", path);

    hFind = FindFirstFileW(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    BOOL result = TRUE;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 ||
            wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }

        wchar_t fullPath[MAX_PATH];
        _snwprintf_s(fullPath, MAX_PATH, _TRUNCATE, L"%s\\%s", path, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            result &= DeleteDirectoryRecursive(fullPath, Stats);
            if (RemoveDirectoryW(fullPath)) {
                Stats->FoldersCleaned++;
            }
        } else {
            SecureWipeFileInternal(fullPath);
            Stats->FilesDeleted++;
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    return result;
}

// ==================== SERVICE CONTROL ====================

BOOL StopService(const wchar_t* serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hService = OpenServiceW(hScm, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hScm);
        return FALSE;
    }

    SERVICE_STATUS status;
    BOOL result = ControlService(hService, SERVICE_CONTROL_STOP, &status);
    
    // Wait for service to stop
    if (result) {
        for (int i = 0; i < 30; i++) {
            Sleep(100);
            if (!QueryServiceStatus(hService, &status)) break;
            if (status.dwCurrentState == SERVICE_STOPPED) break;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
    return result;
}

BOOL StartServiceSimple(const wchar_t* serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hService = OpenServiceW(hScm, serviceName, SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hScm);
        return FALSE;
    }

    BOOL result = StartServiceW(hService, 0, NULL);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
    return result || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
}

BOOL IsServiceRunning(const wchar_t* serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return FALSE;

    SC_HANDLE hService = OpenServiceW(hScm, serviceName, SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hScm);
        return FALSE;
    }

    SERVICE_STATUS status;
    BOOL result = QueryServiceStatus(hService, &status);
    BOOL running = result && status.dwCurrentState == SERVICE_RUNNING;

    CloseServiceHandle(hService);
    CloseServiceHandle(hScm);
    return running;
}

// ==================== REGISTRY OPERATIONS ====================

BOOL DeleteRegistryKeyRecursive(HKEY hKeyRoot, const wchar_t* subKey) {
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    // Enumerate and delete subkeys
    wchar_t keyName[256];
    DWORD keyNameSize = 256;
    DWORD index = 0;

    while (RegEnumKeyExW(hKey, index, keyName, &keyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        wchar_t fullPath[MAX_PATH];
        _snwprintf_s(fullPath, MAX_PATH, _TRUNCATE, L"%s\\%s", subKey, keyName);
        DeleteRegistryKeyRecursive(hKeyRoot, fullPath);
        keyNameSize = 256;
        // Don't increment index, since we deleted the current one
    }

    RegCloseKey(hKey);

    // Delete this key
    return RegDeleteKeyW(hKeyRoot, subKey) == ERROR_SUCCESS;
}

// ==================== SYSTEM INFO ====================

typedef LONG (WINAPI *RtlGetVersionPtr)(OSVERSIONINFOEXW*);

BOOL GetWindowsVersion(OSVERSIONINFOEXW* osvi) {
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return FALSE;

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
    if (!RtlGetVersion) return FALSE;

    memset(osvi, 0, sizeof(*osvi));
    osvi->dwOSVersionInfoSize = sizeof(*osvi);
    
    return RtlGetVersion(osvi) == 0;
}

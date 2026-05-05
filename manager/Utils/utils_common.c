/*
 * HWID Spoofer - Utils Module
 * Common utility functions
 */

#include "utils_common.h"

// ==================== DEBUG LOGGING ====================

void DbgLog(const char* fmt, ...) {
    FILE* fp = NULL;
    fopen_s(&fp, "hwid_debug.log", "a");
    if (!fp) return;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(fp, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    
    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    
    fprintf(fp, "\n");
    fclose(fp);
}

void SetLastMapFailV(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsprintf_s(g_LastMapFail, sizeof(g_LastMapFail), fmt, ap);
    va_end(ap);
}

void ClearLastMapFail(void) { 
    g_LastMapFail[0] = 0; 
}

// ==================== ADMIN CHECK ====================

BOOL IsAdmin(void) {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// ==================== ENVIRONMENT CHECK ====================

BOOL KM_AllowUnsafeKernelVaProbe(void) {
    char v[8] = {0};
    DWORD n = GetEnvironmentVariableA("HWID_ALLOW_UNSAFE_KVA_PTE_SCAN", v, (DWORD)sizeof(v));
    if (n == 0 || n >= sizeof(v))
        return FALSE;
    return (v[0] == '1' || v[0] == 'y' || v[0] == 'Y' || v[0] == 't' || v[0] == 'T');
}

// ==================== TEMP DIRECTORY ====================

BOOL CreateHiddenTempDirectory(void) {
    if (g_TempDir[0] != '\0') return TRUE;
    
    char tempPath[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tempPath)) return FALSE;
    
    char randomName[16];
    GenerateRandomHexName(randomName, sizeof(randomName));
    
    _snprintf_s(g_TempDir, sizeof(g_TempDir), _TRUNCATE, "%s%s", tempPath, randomName);
    
    if (!CreateDirectoryA(g_TempDir, NULL)) {
        g_TempDir[0] = '\0';
        return FALSE;
    }
    
    // Hide the directory
    SetFileAttributesA(g_TempDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    return TRUE;
}

void CleanupTempFiles(void) {
    if (g_TempDir[0] == '\0') return;
    
    // Remove all files in temp dir
    char searchPath[MAX_PATH];
    _snprintf_s(searchPath, sizeof(searchPath), _TRUNCATE, "%s\\*", g_TempDir);
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                continue;
            
            char filePath[MAX_PATH];
            _snprintf_s(filePath, sizeof(filePath), _TRUNCATE, "%s\\%s", g_TempDir, findData.cFileName);
            
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                RemoveDirectoryA(filePath);
            } else {
                SecureWipeFile(filePath);
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    RemoveDirectoryA(g_TempDir);
    g_TempDir[0] = '\0';
}

// ==================== RESOURCE EXTRACTION ====================

BOOL ExtractResource(int resourceId, const char* outputPath) {
    HRSRC hRes = FindResourceA(g_hInst, MAKEINTRESOURCEA(resourceId), RT_RCDATA);
    if (!hRes) return FALSE;
    
    HGLOBAL hData = LoadResource(g_hInst, hRes);
    DWORD resSize = SizeofResource(g_hInst, hRes);
    PVOID resData = hData ? LockResource(hData) : NULL;
    if (!resData || resSize == 0) return FALSE;
    
    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD written = 0;
    BOOL result = WriteFile(hFile, resData, resSize, &written, NULL);
    CloseHandle(hFile);
    
    return result && (written == resSize);
}

BOOL ExtractDriverFiles(void) {
    if (!CreateHiddenTempDirectory()) return FALSE;
    
    // Extract vulnerable driver
    _snprintf_s(g_VulnDriverPath, sizeof(g_VulnDriverPath), _TRUNCATE,
                "%s\\vuln_driver.sys", g_TempDir);
    
    if (!ExtractResource(IDR_VULN_DRIVER, g_VulnDriverPath)) {
        DbgLog("Failed to extract vulnerable driver");
        return FALSE;
    }
    
    // Generate random service name
    char randomService[16];
    GenerateRandomHexName(randomService, sizeof(randomService));
    strncpy_s(g_VulnServiceName, sizeof(g_VulnServiceName), randomService, _TRUNCATE);
    
    // Generate random device name
    char randomDevice[16];
    GenerateRandomHexName(randomDevice, sizeof(randomDevice));
    strncpy_s(g_VulnDeviceName, sizeof(g_VulnDeviceName), randomDevice, _TRUNCATE);
    
    return TRUE;
}

// ==================== FILE OPERATIONS ====================

void SecureWipeFile(const char* path) {
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                              FILE_FLAG_WRITE_THROUGH, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart == 0) {
        CloseHandle(hFile);
        DeleteFileA(path);
        return;
    }
    
    // Overwrite with zeros
    BYTE buffer[4096] = {0};
    DWORD written;
    SetFilePointerEx(hFile, (LARGE_INTEGER){0}, NULL, FILE_BEGIN);
    
    LONGLONG remaining = size.QuadPart;
    while (remaining > 0) {
        DWORD toWrite = (DWORD)((remaining < 4096) ? remaining : 4096);
        WriteFile(hFile, buffer, toWrite, &written, NULL);
        remaining -= written;
    }
    
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    DeleteFileA(path);
}

void GenerateRandomHexName(char* buffer, size_t len) {
    const char hexChars[] = "0123456789ABCDEF";
    size_t nameLen = (len > 12) ? 12 : len - 1;
    
    srand((unsigned int)GetTickCount64() ^ (unsigned int)time(NULL));
    
    for (size_t i = 0; i < nameLen; i++) {
        buffer[i] = hexChars[rand() % 16];
    }
    buffer[nameLen] = '\0';
}

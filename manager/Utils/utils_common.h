/*
 * HWID Spoofer - Utils Module Header
 * Common utility functions
 */

#ifndef UTILS_COMMON_H
#define UTILS_COMMON_H

#include "../manager.h"

#ifdef __cplusplus
extern "C" {
#endif

// Debug logging
void DbgLog(const char* fmt, ...);
void SetLastMapFailV(const char* fmt, ...);
void ClearLastMapFail(void);

// Admin check
BOOL IsAdmin(void);

// Temp directory and file operations
BOOL CreateHiddenTempDirectory(void);
BOOL ExtractResource(int resourceId, const char* outputPath);
BOOL ExtractDriverFiles(void);
void SecureWipeFile(const char* path);
void CleanupTempFiles(void);
void GenerateRandomHexName(char* buffer, size_t len);

// Environment check
BOOL KM_AllowUnsafeKernelVaProbe(void);

// HWID log operations
BOOL ReadHwidLog(void);
void SaveHwidLogToDocuments(void);

#ifdef __cplusplus
}
#endif

#endif // UTILS_COMMON_H

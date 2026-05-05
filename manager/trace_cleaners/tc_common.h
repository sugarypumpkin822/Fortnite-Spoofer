/*
 * Trace Cleaners - Common Functions Header
 * Shared utility functions for all trace cleaners
 */

#ifndef TC_COMMON_H
#define TC_COMMON_H

#include "../trace_cleaner.h"
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Secure file wiping - internal implementation
void SecureWipeFileInternal(const wchar_t* path);

// Recursively delete directory
BOOL DeleteDirectoryRecursive(const wchar_t* path, CLEAN_STATS* Stats);

// Stop a Windows service
BOOL StopService(const wchar_t* serviceName);

// Start a Windows service  
BOOL StartServiceSimple(const wchar_t* serviceName);

// Check if service is running
BOOL IsServiceRunning(const wchar_t* serviceName);

// Delete registry key recursively
BOOL DeleteRegistryKeyRecursive(HKEY hKeyRoot, const wchar_t* subKey);

// Get Windows version info
BOOL GetWindowsVersion(OSVERSIONINFOEXW* osvi);

#ifdef __cplusplus
}
#endif

#endif // TC_COMMON_H

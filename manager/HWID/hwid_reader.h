/*
 * HWID Spoofer - HWID Reader Module Header
 * Hardware ID reading functions
 */

#ifndef HWID_READER_H
#define HWID_READER_H

#include "../manager.h"

#ifdef __cplusplus
extern "C" {
#endif

// Read all HWIDs on startup
void ReadAllHWIDs(void);

// Individual HWID readers
BOOL GetDiskSerial(char* buffer, size_t bufferSize);
BOOL GetMACAddress(UCHAR* mac);
BOOL GetBIOSSerial(char* buffer, size_t bufferSize);
BOOL GetBoardSerial(char* buffer, size_t bufferSize);
BOOL GetSystemUUID(char* buffer, size_t bufferSize);
BOOL GetVolumeSerialNum(ULONG* serial);
BOOL GetGPUID(char* buffer, size_t bufferSize);

// Refresh current values
void RefreshCurrentHWIDs(void);

// SMBIOS helper
static BOOL GetSMBIOSString(BYTE smbType, BYTE strOffset, char* buffer, size_t bufferSize);

// HWID Log operations
BOOL ReadHwidLog(void);
void SaveHwidLogToDocuments(void);

#ifdef __cplusplus
}
#endif

#endif // HWID_READER_H

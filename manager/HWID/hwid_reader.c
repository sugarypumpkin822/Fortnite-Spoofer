/*
 * HWID Spoofer - HWID Reader Module
 * Hardware ID reading functions
 */

#include "hwid_reader.h"

// ==================== DISK SERIAL ====================

typedef struct {
    DWORD PropertyId;
    DWORD QueryType;
    BYTE  AdditionalParameters[1];
} STOR_PROP_QUERY;

typedef struct {
    DWORD Version;
    DWORD Size;
    BYTE  DeviceType;
    BYTE  DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    DWORD VendorIdOffset;
    DWORD ProductIdOffset;
    DWORD ProductRevisionOffset;
    DWORD SerialNumberOffset;
    DWORD BusType;
    DWORD RawPropertiesLength;
    BYTE  RawDeviceProperties[1];
} STOR_DEV_DESC;

BOOL GetDiskSerial(char* buffer, size_t bufferSize) {
    HANDLE hDevice = CreateFileA("\\\\.\\PhysicalDrive0", 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;

    STOR_PROP_QUERY query = {0};
    BYTE outBuf[1024] = {0};
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(hDevice, 0x002D1400,
        &query, sizeof(query), outBuf, sizeof(outBuf), &bytesReturned, NULL);
    CloseHandle(hDevice);

    if (!result || bytesReturned < sizeof(STOR_DEV_DESC)) return FALSE;

    STOR_DEV_DESC* desc = (STOR_DEV_DESC*)outBuf;
    if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < bytesReturned) {
        char* serial = (char*)(outBuf + desc->SerialNumberOffset);
        while (*serial == ' ') serial++;
        size_t len = strlen(serial);
        while (len > 0 && serial[len - 1] == ' ') { serial[--len] = '\0'; }
        if (*serial) {
            strncpy_s(buffer, bufferSize, serial, _TRUNCATE);
            return TRUE;
        }
    }
    return FALSE;
}

// ==================== MAC ADDRESS ====================

BOOL GetMACAddress(UCHAR* mac) {
    PIP_ADAPTER_INFO adapterInfo = NULL;
    ULONG bufferSize = 0;

    GetAdaptersInfo(NULL, &bufferSize);
    if (bufferSize == 0) return FALSE;

    adapterInfo = (PIP_ADAPTER_INFO)malloc(bufferSize);
    if (!adapterInfo) return FALSE;

    BOOL found = FALSE;
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapterInfo;
        while (adapter) {
            if (adapter->Type == MIB_IF_TYPE_ETHERNET ||
                adapter->Type == IF_TYPE_IEEE80211) {
                memcpy(mac, adapter->Address, 6);
                found = TRUE;
                break;
            }
            adapter = adapter->Next;
        }
    }
    free(adapterInfo);
    return found;
}

// ==================== SMBIOS HELPERS ====================

typedef struct {
    BYTE  Method; BYTE MajVer; BYTE MinVer; BYTE DmiRev; DWORD Length;
} SMB_HDR;

static BOOL GetSMBIOSString(BYTE smbType, BYTE strOffset, char* buffer, size_t bufferSize) {
    DWORD fwSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (fwSize == 0) return FALSE;

    BYTE* data = (BYTE*)malloc(fwSize);
    if (!data) return FALSE;

    if (GetSystemFirmwareTable('RSMB', 0, data, fwSize) != fwSize) {
        free(data);
        return FALSE;
    }

    if (fwSize < sizeof(SMB_HDR)) {
        free(data);
        return FALSE;
    }

    SMB_HDR* hdr = (SMB_HDR*)data;
    if (hdr->Length == 0 || hdr->Length > fwSize - sizeof(SMB_HDR)) {
        free(data);
        return FALSE;
    }
    BYTE* tbl = data + sizeof(SMB_HDR);
    BYTE* tblEnd = tbl + hdr->Length;
    BYTE* ptr = tbl;
    BOOL found = FALSE;

    while (ptr + 4 < tblEnd) {
        BYTE type = ptr[0];
        BYTE length = ptr[1];
        if (length < 4) break;

        if (type == smbType && length > strOffset) {
            BYTE strIdx = ptr[strOffset];
            if (strIdx > 0) {
                BYTE* strings = ptr + length;
                BYTE num = 1;
                while (strings < tblEnd && num < strIdx) {
                    if (*strings == '\0') num++;
                    strings++;
                }
                if (strings < tblEnd) {
                    strncpy_s(buffer, bufferSize, (char*)strings, _TRUNCATE);
                    found = (buffer[0] != '\0');
                }
            }
        }
        
        // Move to next structure
        BYTE* end = ptr + length;
        while (end < tblEnd && !(end[0] == '\0' && end[1] == '\0')) end++;
        if (end >= tblEnd) break;
        ptr = end + 2;
    }

    free(data);
    return found;
}

BOOL GetBIOSSerial(char* buffer, size_t bufferSize) {
    // SMBIOS Type 1, string at offset 0x04
    return GetSMBIOSString(0x01, 0x04, buffer, bufferSize);
}

BOOL GetBoardSerial(char* buffer, size_t bufferSize) {
    // SMBIOS Type 2, string at offset 0x07
    return GetSMBIOSString(0x02, 0x07, buffer, bufferSize);
}

BOOL GetSystemUUID(char* buffer, size_t bufferSize) {
    // SMBIOS Type 1, UUID at offset 0x08 (16 bytes)
    DWORD fwSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (fwSize == 0) return FALSE;

    BYTE* data = (BYTE*)malloc(fwSize);
    if (!data) return FALSE;

    if (GetSystemFirmwareTable('RSMB', 0, data, fwSize) != fwSize) {
        free(data);
        return FALSE;
    }

    SMB_HDR* hdr = (SMB_HDR*)data;
    BYTE* tbl = data + sizeof(SMB_HDR);
    BYTE* tblEnd = tbl + hdr->Length;
    BYTE* ptr = tbl;
    BOOL found = FALSE;

    while (ptr + 4 < tblEnd) {
        BYTE type = ptr[0];
        BYTE length = ptr[1];
        if (length < 4) break;

        if (type == 0x01 && length >= 0x18) {
            // Found Type 1 (System Information), UUID at offset 0x08
            BYTE* uuid = ptr + 0x08;
            sprintf_s(buffer, bufferSize, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                uuid[0], uuid[1], uuid[2], uuid[3],
                uuid[4], uuid[5], uuid[6], uuid[7],
                uuid[8], uuid[9], uuid[10], uuid[11],
                uuid[12], uuid[13], uuid[14], uuid[15]);
            found = TRUE;
            break;
        }
        
        BYTE* end = ptr + length;
        while (end < tblEnd && !(end[0] == '\0' && end[1] == '\0')) end++;
        if (end >= tblEnd) break;
        ptr = end + 2;
    }

    free(data);
    return found;
}

// ==================== VOLUME SERIAL ====================

BOOL GetVolumeSerialNum(ULONG* serial) {
    char sysDir[MAX_PATH];
    if (!GetSystemDirectoryA(sysDir, MAX_PATH)) return FALSE;
    
    // Extract drive letter
    char drive[4] = { sysDir[0], ':', '\\', '\0' };
    
    DWORD serialNum = 0;
    if (!GetVolumeInformationA(drive, NULL, 0, &serialNum, NULL, NULL, NULL, 0))
        return FALSE;
    
    *serial = serialNum;
    return TRUE;
}

// ==================== GPU ID ====================

BOOL GetGPUID(char* buffer, size_t bufferSize) {
    DISPLAY_DEVICEA dd = {0};
    dd.cb = sizeof(dd);
    
    if (EnumDisplayDevicesA(NULL, 0, &dd, 0)) {
        strncpy_s(buffer, bufferSize, dd.DeviceString, _TRUNCATE);
        return TRUE;
    }
    
    return FALSE;
}

// ==================== READ ALL HWIDS ====================

void ReadAllHWIDs(void) {
    // Disk Serial
    if (GetDiskSerial(g_OriginalDiskSerial, sizeof(g_OriginalDiskSerial))) {
        DbgLog("Original Disk Serial: %s", g_OriginalDiskSerial);
    }
    
    // MAC Address
    g_OriginalMACValid = GetMACAddress(g_OriginalMAC);
    if (g_OriginalMACValid) {
        DbgLog("Original MAC: %02X:%02X:%02X:%02X:%02X:%02X",
            g_OriginalMAC[0], g_OriginalMAC[1], g_OriginalMAC[2],
            g_OriginalMAC[3], g_OriginalMAC[4], g_OriginalMAC[5]);
    }
    
    // BIOS Serial
    if (GetBIOSSerial(g_OrigBIOSSerial, sizeof(g_OrigBIOSSerial))) {
        DbgLog("Original BIOS Serial: %s", g_OrigBIOSSerial);
    }
    
    // Board Serial
    if (GetBoardSerial(g_OrigBoardSerial, sizeof(g_OrigBoardSerial))) {
        DbgLog("Original Board Serial: %s", g_OrigBoardSerial);
    }
    
    // System UUID
    if (GetSystemUUID(g_OrigSystemUUID, sizeof(g_OrigSystemUUID))) {
        DbgLog("Original System UUID: %s", g_OrigSystemUUID);
    }
    
    // Volume Serial
    g_OrigVolumeSerialValid = GetVolumeSerialNum(&g_OrigVolumeSerial);
    if (g_OrigVolumeSerialValid) {
        DbgLog("Original Volume Serial: %08X", g_OrigVolumeSerial);
    }
    
    // GPU ID
    if (GetGPUID(g_OrigGPUID, sizeof(g_OrigGPUID))) {
        DbgLog("Original GPU ID: %s", g_OrigGPUID);
    }
    
    // Copy to current
    strcpy_s(g_CurrentDiskSerial, sizeof(g_CurrentDiskSerial), g_OriginalDiskSerial);
    memcpy(g_CurrentMAC, g_OriginalMAC, 6);
    g_CurrentMACValid = g_OriginalMACValid;
    strcpy_s(g_CurrBIOSSerial, sizeof(g_CurrBIOSSerial), g_OrigBIOSSerial);
    strcpy_s(g_CurrBoardSerial, sizeof(g_CurrBoardSerial), g_OrigBoardSerial);
    strcpy_s(g_CurrSystemUUID, sizeof(g_CurrSystemUUID), g_OrigSystemUUID);
    g_CurrVolumeSerial = g_OrigVolumeSerial;
    g_CurrVolumeSerialValid = g_OrigVolumeSerialValid;
    strcpy_s(g_CurrGPUID, sizeof(g_CurrGPUID), g_OrigGPUID);
}

void RefreshCurrentHWIDs(void) {
    // Refresh MAC address
    UCHAR currMAC[6];
    if (GetMACAddress(currMAC)) {
        memcpy(g_CurrentMAC, currMAC, 6);
        g_CurrentMACValid = TRUE;
    }
    
    // Refresh volume serial
    ULONG volSerial;
    if (GetVolumeSerialNum(&volSerial)) {
        g_CurrVolumeSerial = volSerial;
        g_CurrVolumeSerialValid = TRUE;
    }
}

// ==================== HWID LOG OPERATIONS ====================

BOOL ReadHwidLog(void) {
    // Read from driver's log file if it exists
    // This would read from a file created by the driver
    // For now, placeholder
    return FALSE;
}

void SaveHwidLogToDocuments(void) {
    char docPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, docPath))) {
        char logPath[MAX_PATH];
        _snprintf_s(logPath, sizeof(logPath), _TRUNCATE, "%s\\hwid_backup.txt", docPath);
        
        FILE* fp = NULL;
        fopen_s(&fp, logPath, "w");
        if (fp) {
            fprintf(fp, "=== HWID Backup ===\n\n");
            fprintf(fp, "Disk Serial: %s\n", g_OriginalDiskSerial);
            fprintf(fp, "BIOS Serial: %s\n", g_OrigBIOSSerial);
            fprintf(fp, "Board Serial: %s\n", g_OrigBoardSerial);
            fprintf(fp, "System UUID: %s\n", g_OrigSystemUUID);
            fprintf(fp, "MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                g_OriginalMAC[0], g_OriginalMAC[1], g_OriginalMAC[2],
                g_OriginalMAC[3], g_OriginalMAC[4], g_OriginalMAC[5]);
            fclose(fp);
        }
    }
}

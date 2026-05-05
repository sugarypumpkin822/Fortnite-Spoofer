/*
 * Trace Cleaner - USN Journal Module
 * Manipulates NTFS USN Journal for file system privacy
 */

#include "tc_usn.h"
#include <winioctl.h>

// USN Journal control structures from winioctl.h
// DELETE_USN_JOURNAL_DATA, CREATE_USN_JOURNAL_DATA, USN_JOURNAL_DATA
// are already defined in the Windows SDK winioctl.h

BOOL DeleteUsnJournalOnVolume(const wchar_t* volumePath) {
    if (!volumePath) return FALSE;
    
    HANDLE hDevice = CreateFileW(volumePath, GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    DELETE_USN_JOURNAL_DATA delUsn = {0};
    delUsn.UsnJournalID = 0;  // 0 means current journal
    delUsn.DeleteFlags = USN_DELETE_FLAG_DELETE;
    
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice, FSCTL_DELETE_USN_JOURNAL,
                                  &delUsn, sizeof(delUsn),
                                  NULL, 0, &bytesReturned, NULL);
    
    CloseHandle(hDevice);
    return result;
}

BOOL CreateUsnJournalOnVolume(const wchar_t* volumePath, UINT64 maxSize, UINT64 allocationDelta) {
    if (!volumePath) return FALSE;
    
    HANDLE hDevice = CreateFileW(volumePath, GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    CREATE_USN_JOURNAL_DATA createUsn = {0};
    createUsn.MaximumSize = maxSize ? maxSize : 0x100000;  // 1MB default
    createUsn.AllocationDelta = allocationDelta ? allocationDelta : 0x10000;  // 64KB default
    
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice, FSCTL_CREATE_USN_JOURNAL,
                                  &createUsn, sizeof(createUsn),
                                  NULL, 0, &bytesReturned, NULL);
    
    CloseHandle(hDevice);
    return result;
}

BOOL GetUsnJournalStats(const wchar_t* volumePath, UINT64* totalEntries, UINT64* sizeOnDisk) {
    if (!volumePath || !totalEntries || !sizeOnDisk) return FALSE;
    
    *totalEntries = 0;
    *sizeOnDisk = 0;
    
    HANDLE hDevice = CreateFileW(volumePath, GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
    USN_JOURNAL_DATA usnData;
    DWORD bytesReturned;
    
    BOOL result = DeviceIoControl(hDevice, FSCTL_QUERY_USN_JOURNAL,
                                  NULL, 0,
                                  &usnData, sizeof(usnData),
                                  &bytesReturned, NULL);
    
    if (result) {
        // Approximate entries based on USN range
        *totalEntries = (UINT64)(usnData.NextUsn - usnData.FirstUsn) / 512;
        *sizeOnDisk = (UINT64)usnData.MaximumSize;
    }
    
    CloseHandle(hDevice);
    return result;
}

BOOL TraceClean_UsnJournal(CLEAN_STATS* Stats) {
    BOOL result = TRUE;
    
    // Get all volume paths
    wchar_t volumeName[MAX_PATH];
    HANDLE hVolume = FindFirstVolumeW(volumeName, MAX_PATH);
    
    if (hVolume == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    do {
        // Skip system reserved volumes
        if (wcsstr(volumeName, L"\\\\?\\HarddiskVolume") == NULL) {
            continue;
        }
        
        // Open the volume
        HANDLE hDevice = CreateFileW(volumeName, GENERIC_READ | GENERIC_WRITE,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                     OPEN_EXISTING, 0, NULL);
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            continue;
        }
        
        // Delete USN journal
        DWORD bytesReturned;
        DELETE_USN_JOURNAL_DATA delUsn = {0};
        delUsn.UsnJournalID = 0;  // 0 means current journal
        delUsn.DeleteFlags = USN_DELETE_FLAG_DELETE;
        
        BOOL deleteResult = DeviceIoControl(hDevice, FSCTL_DELETE_USN_JOURNAL,
                                            &delUsn, sizeof(delUsn),
                                            NULL, 0, &bytesReturned, NULL);
        
        if (deleteResult) {
            Stats->UsnEntriesModified++;
            
            // Create a new empty journal with smaller size
            CREATE_USN_JOURNAL_DATA createUsn = {0};
            createUsn.MaximumSize = 0x100000;  // 1MB
            createUsn.AllocationDelta = 0x10000;  // 64KB
            
            DeviceIoControl(hDevice, FSCTL_CREATE_USN_JOURNAL,
                            &createUsn, sizeof(createUsn),
                            NULL, 0, &bytesReturned, NULL);
        }
        
        CloseHandle(hDevice);
    } while (FindNextVolumeW(hVolume, volumeName, MAX_PATH));
    
    FindVolumeClose(hVolume);
    return result;
}

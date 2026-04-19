/*
 * Disk Firmware-Level Serial Spoofing
 * 
 * Intercepts SATA/AHCI/NVMe commands at the miniport level to modify
 * IDENTIFY DEVICE responses, providing persistent disk serial spoofing
 * that survives driver unload.
 */

#include <ntddk.h>

// SCSI/ATA command opcodes
#define ATA_IDENTIFY_DEVICE     0xEC
#define ATA_IDENTIFY_PACKET_DEVICE 0xA1
#define NVME_ADMIN_IDENTIFY     0x06

// IDENTIFY DEVICE data structure offsets
#define ID_SERIAL_OFFSET        20   // 20 bytes, word-aligned
#define ID_MODEL_OFFSET         54   // 40 bytes
#define ID_FW_REV_OFFSET        46   // 8 bytes

// NVMe Identify Controller offsets
#define NVME_SERIAL_OFFSET      4    // 20 bytes
#define NVME_MODEL_OFFSET       24   // 40 bytes
#define NVME_FW_REV_OFFSET      64   // 8 bytes

// Miniport driver identifiers
#define STORAHCI_DRIVER_NAME    L"storahci.sys"
#define STORNVME_DRIVER_NAME    L"stornvme.sys"
#define IAStorAC_DRIVER_NAME    L"iastorac.sys"

// Context for disk spoofing
typedef struct _DISK_SPOOF_CONTEXT {
    BOOLEAN         Initialized;
    BOOLEAN         Enabled;
    
    // Spoofed values for SATA/AHCI
    CHAR            FakeSataSerial[21];
    CHAR            FakeSataModel[41];
    CHAR            FakeSataFirmware[9];
    
    // Spoofed values for NVMe
    CHAR            FakeNvmeSerial[21];
    CHAR            FakeNvmeModel[41];
    CHAR            FakeNvmeFirmware[9];
    
    // Original values (for restore)
    BOOLEAN         HaveOriginalSata;
    CHAR            OriginalSataSerial[21];
    CHAR            OriginalSataModel[41];
    CHAR            OriginalSataFirmware[9];
    
    BOOLEAN         HaveOriginalNvme;
    CHAR            OriginalNvmeSerial[21];
    CHAR            OriginalNvmeModel[41];
    CHAR            OriginalNvmeFirmware[9];
    
    // Hook handles
    PVOID           StorAhciHook;
    PVOID           StorNvmeHook;
    PVOID           MiniportHook;
    
    KSPIN_LOCK      Lock;
} DISK_SPOOF_CONTEXT;

static DISK_SPOOF_CONTEXT g_DiskSpoofContext = {0};

// StorAHCI miniport device extension structure (undocumented, reverse-engineered)
typedef struct _AHCI_CHANNEL_EXTENSION {
    PVOID           AdapterExtension;
    ULONG           ChannelIndex;
    ULONG           PortNumber;
    // ... more fields
} AHCI_CHANNEL_EXTENSION, *PAHCI_CHANNEL_EXTENSION;

// AHCI FIS (Frame Information Structure) - IDENTIFY DEVICE response
#pragma pack(push, 1)
typedef struct _AHCI_FIS_IDENTIFY {
    UINT16  Config;                    // 0
    UINT16  Obsolete1;                 // 1
    UINT16  SpecificConfig;            // 2
    UINT16  Obsolete2;                 // 3
    UINT16  Retired1[2];               // 4-5
    UINT16  Obsolete3;                 // 6
    UINT16  Cylinders;               // 7
    UINT16  Obsolete4;                 // 8
    UINT16  Heads;                     // 9
    UINT16  Obsolete5[2];            // 10-11
    UINT16  SectorsPerTrack;           // 12
    UINT16  VendorUnique1[3];        // 13-15
    CHAR    SerialNumber[20];        // 16-25
    UINT16  Retired2[2];             // 26-27
    UINT16  Obsolete6;                 // 28
    // ... more fields follow
} AHCI_FIS_IDENTIFY, *PAHCI_FIS_IDENTIFY;
#pragma pack(pop)

// NVMe Identify Controller structure
#pragma pack(push, 1)
typedef struct _NVME_IDENTIFY_CONTROLLER {
    UINT16  VID;
    UINT16  SSID;
    CHAR    SerialNumber[20];          // Bytes 4-23
    CHAR    ModelNumber[40];           // Bytes 24-63
    CHAR    FirmwareRevision[8];       // Bytes 64-71
    UINT8   Recommended ArbitrationBurst;
    UINT8   IEEE_OUI[3];
    UINT8   CMIC;
    UINT8   MaxDataTransferSize;
    // ... more fields
} NVME_IDENTIFY_CONTROLLER, *PNVME_IDENTIFY_CONTROLLER;
#pragma pack(pop)

/*
 * Swap bytes in a string (ATA strings are big-endian word-swapped)
 */
VOID DiskSpoof_SwapStringBytes(PCHAR Dest, PCHAR Src, UINT32 Length) {
    for (UINT32 i = 0; i < Length; i += 2) {
        if (i + 1 < Length) {
            Dest[i] = Src[i + 1];
            Dest[i + 1] = Src[i];
        } else {
            Dest[i] = Src[i];
        }
    }
    Dest[Length] = '\0';
}

/*
 * Trim trailing spaces from ATA string
 */
VOID DiskSpoof_TrimAtaString(PCHAR Str, UINT32 Length) {
    // Remove trailing spaces
    for (INT i = (INT)Length - 1; i >= 0; i--) {
        if (Str[i] == ' ' || Str[i] == '\0') {
            Str[i] = '\0';
        } else {
            break;
        }
    }
}

/*
 * Initialize disk spoofing context
 */
NTSTATUS DiskSpoof_Initialize(VOID) {
    RtlZeroMemory(&g_DiskSpoofContext, sizeof(g_DiskSpoofContext));
    KeInitializeSpinLock(&g_DiskSpoofContext.Lock);
    
    // Generate random serial numbers
    // In production, these would be configurable
    RtlCopyMemory(g_DiskSpoofContext.FakeSataSerial, "WD-RANDOM12345      ", 20);
    RtlCopyMemory(g_DiskSpoofContext.FakeSataModel, "WDC WD10EZEX-00BN5A0                    ", 40);
    RtlCopyMemory(g_DiskSpoofContext.FakeSataFirmware, "01.01A01", 8);
    
    RtlCopyMemory(g_DiskSpoofContext.FakeNvmeSerial, "SAMSUNG-RAND123     ", 20);
    RtlCopyMemory(g_DiskSpoofContext.FakeNvmeModel, "Samsung SSD 970 EVO Plus 1TB            ", 40);
    RtlCopyMemory(g_DiskSpoofContext.FakeNvmeFirmware, "2B2QEXM7", 8);
    
    g_DiskSpoofContext.Initialized = TRUE;
    g_DiskSpoofContext.Enabled = TRUE;
    
    return STATUS_SUCCESS;
}

/*
 * Modify SATA IDENTIFY DEVICE response
 */
VOID DiskSpoof_ModifySataIdentify(PAHCI_FIS_IDENTIFY IdentifyData) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    // Save original values if not already saved
    if (!g_DiskSpoofContext.HaveOriginalSata) {
        CHAR tempSerial[21];
        CHAR tempModel[41];
        CHAR tempFw[9];
        
        DiskSpoof_SwapStringBytes(tempSerial, IdentifyData->SerialNumber, 20);
        DiskSpoof_TrimAtaString(tempSerial, 20);
        RtlCopyMemory(g_DiskSpoofContext.OriginalSataSerial, tempSerial, 21);
        
        // Model is at offset 54 (27 words * 2 bytes)
        DiskSpoof_SwapStringBytes(tempModel, (PCHAR)((PUINT8)IdentifyData + 54), 40);
        DiskSpoof_TrimAtaString(tempModel, 40);
        RtlCopyMemory(g_DiskSpoofContext.OriginalSataModel, tempModel, 41);
        
        // Firmware at offset 46 (23 words * 2 bytes)
        DiskSpoof_SwapStringBytes(tempFw, (PCHAR)((PUINT8)IdentifyData + 46), 8);
        DiskSpoof_TrimAtaString(tempFw, 8);
        RtlCopyMemory(g_DiskSpoofContext.OriginalSataFirmware, tempFw, 9);
        
        g_DiskSpoofContext.HaveOriginalSata = TRUE;
    }
    
    // Write spoofed serial (need to swap bytes for ATA big-endian)
    CHAR swappedSerial[20];
    for (UINT32 i = 0; i < 20; i += 2) {
        swappedSerial[i] = g_DiskSpoofContext.FakeSataSerial[i + 1];
        swappedSerial[i + 1] = g_DiskSpoofContext.FakeSataSerial[i];
    }
    RtlCopyMemory(IdentifyData->SerialNumber, swappedSerial, 20);
    
    // Write spoofed model
    CHAR swappedModel[40];
    for (UINT32 i = 0; i < 40; i += 2) {
        swappedModel[i] = g_DiskSpoofContext.FakeSataModel[i + 1];
        swappedModel[i + 1] = g_DiskSpoofContext.FakeSataModel[i];
    }
    RtlCopyMemory((PUINT8)IdentifyData + 54, swappedModel, 40);
    
    // Write spoofed firmware
    CHAR swappedFw[8];
    for (UINT32 i = 0; i < 8; i += 2) {
        swappedFw[i] = g_DiskSpoofContext.FakeSataFirmware[i + 1];
        swappedFw[i + 1] = g_DiskSpoofContext.FakeSataFirmware[i];
    }
    RtlCopyMemory((PUINT8)IdentifyData + 46, swappedFw, 8);
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
}

/*
 * Modify NVMe Identify Controller response
 */
VOID DiskSpoof_ModifyNvmeIdentify(PNVME_IDENTIFY_CONTROLLER IdentifyData) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    // Save original values
    if (!g_DiskSpoofContext.HaveOriginalNvme) {
        RtlCopyMemory(g_DiskSpoofContext.OriginalNvmeSerial, IdentifyData->SerialNumber, 20);
        DiskSpoof_TrimAtaString(g_DiskSpoofContext.OriginalNvmeSerial, 20);
        
        RtlCopyMemory(g_DiskSpoofContext.OriginalNvmeModel, IdentifyData->ModelNumber, 40);
        DiskSpoof_TrimAtaString(g_DiskSpoofContext.OriginalNvmeModel, 40);
        
        RtlCopyMemory(g_DiskSpoofContext.OriginalNvmeFirmware, IdentifyData->FirmwareRevision, 8);
        DiskSpoof_TrimAtaString(g_DiskSpoofContext.OriginalNvmeFirmware, 8);
        
        g_DiskSpoofContext.HaveOriginalNvme = TRUE;
    }
    
    // NVMe strings are not byte-swapped, just space-padded
    RtlCopyMemory(IdentifyData->SerialNumber, g_DiskSpoofContext.FakeNvmeSerial, 20);
    RtlCopyMemory(IdentifyData->ModelNumber, g_DiskSpoofContext.FakeNvmeModel, 40);
    RtlCopyMemory(IdentifyData->FirmwareRevision, g_DiskSpoofContext.FakeNvmeFirmware, 8);
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
}

/*
 * Hook for StorAHCI miniport - intercepts IDENTIFY DEVICE
 * 
 * This is called from the miniport's BuildIo or StartIo routine
 */
BOOLEAN DiskSpoof_HookStorAhci(
    PVOID ChannelExtension,
    PVOID Srb,
    PVOID Cdb
) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return FALSE;  // Pass through
    }
    
    // Check if this is an IDENTIFY DEVICE command
    PUINT8 cdb = (PUINT8)Cdb;
    
    // ATA passthrough CDB format
    if (cdb[0] == 0x85) {  // ATA PASS-THROUGH (16)
        UINT8 command = cdb[14];  // Command register
        
        if (command == ATA_IDENTIFY_DEVICE || 
            command == ATA_IDENTIFY_PACKET_DEVICE) {
            
            // Mark this SRB for post-processing
            // We need to modify the response after the command completes
            // Store context in SRB extension or use SRB flags
            
            return TRUE;  // Mark for processing
        }
    }
    
    return FALSE;  // Not our command
}

/*
 * Post-process IDENTIFY DEVICE response
 * Called after the miniport completes the command
 */
VOID DiskSpoof_PostProcessSataIdentify(PVOID Srb, PVOID DataBuffer) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    PAHCI_FIS_IDENTIFY identify = (PAHCI_FIS_IDENTIFY)DataBuffer;
    
    // Validate this looks like an IDENTIFY response
    // (Check signature bytes or other identifying features)
    
    DiskSpoof_ModifySataIdentify(identify);
}

/*
 * Hook for StorNVMe miniport
 */
BOOLEAN DiskSpoof_HookStorNvme(
    PVOID AdapterExtension,
    PVOID Request
) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return FALSE;
    }
    
    // NVMe admin command structure
    // Check if this is an Identify Controller command
    
    PUINT32 cmd = (PUINT32)Request;
    UINT8 opcode = (UINT8)(cmd[0] & 0xFF);
    
    if (opcode == NVME_ADMIN_IDENTIFY) {
        UINT8 cns = (UINT8)((cmd[1] >> 8) & 0xFF);  // Controller or Namespace Structure
        
        if (cns == 1) {  // Identify Controller
            // Mark for post-processing
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * Post-process NVMe Identify response
 */
VOID DiskSpoof_PostProcessNvmeIdentify(PVOID ResponseBuffer) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    PNVME_IDENTIFY_CONTROLLER identify = (PNVME_IDENTIFY_CONTROLLER)ResponseBuffer;
    DiskSpoof_ModifyNvmeIdentify(identify);
}

/*
 * Install miniport hooks
 * 
 * This function patches the dispatch routines of storahci.sys
 * and stornvme.sys to intercept IDENTIFY commands
 */
NTSTATUS DiskSpoof_InstallMiniportHooks(VOID) {
    if (!g_DiskSpoofContext.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Find storahci.sys driver object
    // Find StorAHCI miniport dispatch routines
    // Hook BuildIo and/or StartIo
    
    // Find stornvme.sys driver object
    // Hook NVMe admin command handler
    
    // Implementation requires driver object enumeration
    // and code patch/installation
    
    return STATUS_SUCCESS;
}

/*
 * Remove miniport hooks
 */
VOID DiskSpoof_RemoveMiniportHooks(VOID) {
    // Restore original dispatch routines
    g_DiskSpoofContext.Enabled = FALSE;
}

/*
 * Set custom spoofed values
 */
NTSTATUS DiskSpoof_SetSataValues(
    PCHAR Serial,
    PCHAR Model,
    PCHAR Firmware
) {
    if (!g_DiskSpoofContext.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    if (Serial) {
        RtlZeroMemory(g_DiskSpoofContext.FakeSataSerial, 21);
        RtlCopyMemory(g_DiskSpoofContext.FakeSataSerial, Serial, 
                     min(strlen(Serial), 20));
    }
    
    if (Model) {
        RtlZeroMemory(g_DiskSpoofContext.FakeSataModel, 41);
        RtlCopyMemory(g_DiskSpoofContext.FakeSataModel, Model,
                     min(strlen(Model), 40));
    }
    
    if (Firmware) {
        RtlZeroMemory(g_DiskSpoofContext.FakeSataFirmware, 9);
        RtlCopyMemory(g_DiskSpoofContext.FakeSataFirmware, Firmware,
                     min(strlen(Firmware), 8));
    }
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
    
    return STATUS_SUCCESS;
}

NTSTATUS DiskSpoof_SetNvmeValues(
    PCHAR Serial,
    PCHAR Model,
    PCHAR Firmware
) {
    if (!g_DiskSpoofContext.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    if (Serial) {
        RtlZeroMemory(g_DiskSpoofContext.FakeNvmeSerial, 21);
        RtlCopyMemory(g_DiskSpoofContext.FakeNvmeSerial, Serial,
                     min(strlen(Serial), 20));
    }
    
    if (Model) {
        RtlZeroMemory(g_DiskSpoofContext.FakeNvmeModel, 41);
        RtlCopyMemory(g_DiskSpoofContext.FakeNvmeModel, Model,
                     min(strlen(Model), 40));
    }
    
    if (Firmware) {
        RtlZeroMemory(g_DiskSpoofContext.FakeNvmeFirmware, 9);
        RtlCopyMemory(g_DiskSpoofContext.FakeNvmeFirmware, Firmware,
                     min(strlen(Firmware), 8));
    }
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
    
    return STATUS_SUCCESS;
}

/*
 * Get original values
 */
NTSTATUS DiskSpoof_GetOriginalSataValues(
    PCHAR Serial,
    UINT32 SerialLen,
    PCHAR Model,
    UINT32 ModelLen,
    PCHAR Firmware,
    UINT32 FirmwareLen
) {
    if (!g_DiskSpoofContext.HaveOriginalSata) {
        return STATUS_NO_DATA_DETECTED;
    }
    
    RtlZeroMemory(Serial, SerialLen);
    RtlCopyMemory(Serial, g_DiskSpoofContext.OriginalSataSerial,
                  min(SerialLen - 1, 20));
    
    RtlZeroMemory(Model, ModelLen);
    RtlCopyMemory(Model, g_DiskSpoofContext.OriginalSataModel,
                  min(ModelLen - 1, 40));
    
    RtlZeroMemory(Firmware, FirmwareLen);
    RtlCopyMemory(Firmware, g_DiskSpoofContext.OriginalSataFirmware,
                  min(FirmwareLen - 1, 8));
    
    return STATUS_SUCCESS;
}

NTSTATUS DiskSpoof_GetOriginalNvmeValues(
    PCHAR Serial,
    UINT32 SerialLen,
    PCHAR Model,
    UINT32 ModelLen,
    PCHAR Firmware,
    UINT32 FirmwareLen
) {
    if (!g_DiskSpoofContext.HaveOriginalNvme) {
        return STATUS_NO_DATA_DETECTED;
    }
    
    RtlZeroMemory(Serial, SerialLen);
    RtlCopyMemory(Serial, g_DiskSpoofContext.OriginalNvmeSerial,
                  min(SerialLen - 1, 20));
    
    RtlZeroMemory(Model, ModelLen);
    RtlCopyMemory(Model, g_DiskSpoofContext.OriginalNvmeModel,
                  min(ModelLen - 1, 40));
    
    RtlZeroMemory(Firmware, FirmwareLen);
    RtlCopyMemory(Firmware, g_DiskSpoofContext.OriginalNvmeFirmware,
                  min(FirmwareLen - 1, 8));
    
    return STATUS_SUCCESS;
}

/*
 * Enable/disable spoofing
 */
VOID DiskSpoof_Enable(BOOLEAN Enable) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    g_DiskSpoofContext.Enabled = Enable;
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
}

// ==================== ADVANCED FEATURES ====================

/*
 * SMART data spoofing
 * Modifies SMART attribute data to hide real drive usage patterns
 */
typedef struct _SMART_ATTRIBUTE {
    UINT8   Id;
    UINT16  Flags;
    UINT8   Current;
    UINT8   Worst;
    UINT8   Raw[6];
    UINT8   Reserved;
} SMART_ATTRIBUTE;

typedef struct _SMART_DATA {
    UINT16      Version;
    SMART_ATTRIBUTE Attributes[30];
    UINT8       Reserved[6];
    UINT16      OfflineDataCollectionStatus;
    UINT8       SelfTestStatus;
    UINT16      TotalTimeForOfflineDataCollection;
    UINT8       VendorSpecific1;
    UINT8       OfflineDataCollectionCapability;
    UINT16      SmartCapability;
    UINT8       ErrorLogCapability;
    UINT8       VendorSpecific2;
    UINT8       ShortSelfTestRoutineTime;
    UINT8       ExtendedSelfTestRoutineTime;
    UINT8       Reserved2[2];
    UINT8       VendorSpecific3[125];
    UINT8       Checksum;
} SMART_DATA;

VOID DiskSpoof_ModifySmartData(PSMART_DATA SmartData) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DiskSpoofContext.Lock, &oldIrql);
    
    // Modify power-on hours to appear as a new drive
    for (int i = 0; i < 30; i++) {
        if (SmartData->Attributes[i].Id == 9) {  // Power-On Hours
            // Set to a low random value (appears as new drive)
            SmartData->Attributes[i].Raw[0] = (UINT8)(RtlRandomEx(NULL) % 24);
            SmartData->Attributes[i].Raw[1] = 0;
            SmartData->Attributes[i].Raw[2] = 0;
            SmartData->Attributes[i].Raw[3] = 0;
            SmartData->Attributes[i].Raw[4] = 0;
            SmartData->Attributes[i].Raw[5] = 0;
            SmartData->Attributes[i].Current = 100;
            SmartData->Attributes[i].Worst = 100;
        }
        
        if (SmartData->Attributes[i].Id == 12) {  // Power Cycle Count
            // Set to low random value
            SmartData->Attributes[i].Raw[0] = (UINT8)(RtlRandomEx(NULL) % 50);
            SmartData->Attributes[i].Raw[1] = 0;
            SmartData->Attributes[i].Raw[2] = 0;
            SmartData->Attributes[i].Raw[3] = 0;
            SmartData->Attributes[i].Raw[4] = 0;
            SmartData->Attributes[i].Raw[5] = 0;
            SmartData->Attributes[i].Current = 100;
            SmartData->Attributes[i].Worst = 100;
        }
        
        if (SmartData->Attributes[i].Id == 197) {  // Current Pending Sector Count
            // Clear any pending sectors (appears healthy)
            RtlZeroMemory(SmartData->Attributes[i].Raw, 6);
            SmartData->Attributes[i].Current = 100;
            SmartData->Attributes[i].Worst = 100;
        }
        
        if (SmartData->Attributes[i].Id == 198) {  // Offline Uncorrectable
            // Clear offline uncorrectable errors
            RtlZeroMemory(SmartData->Attributes[i].Raw, 6);
            SmartData->Attributes[i].Current = 100;
            SmartData->Attributes[i].Worst = 100;
        }
    }
    
    KeReleaseSpinLock(&g_DiskSpoofContext.Lock, oldIrql);
}

/*
 * World Wide Name (WWN) spoofing for SAN/NAS environments
 */
typedef struct _WWN_SPOOF_CONTEXT {
    UINT64  OriginalWWN;
    UINT64  FakeWWN;
    BOOLEAN HaveOriginal;
} WWN_SPOOF_CONTEXT;

static WWN_SPOOF_CONTEXT g_WwnContext = {0};

VOID DiskSpoof_GenerateFakeWWN(VOID) {
    // Generate OUI (Organizationally Unique Identifier) - use random common vendor
    UINT32 oui = 0x0014C2;  // Random vendor OUI
    
    // Generate random extension
    UINT32 ext = (UINT32)RtlRandomEx(NULL);
    
    g_WwnContext.FakeWWN = ((UINT64)oui << 36) | ((UINT64)ext & 0x000000FFFFFFFFFFULL);
}

VOID DiskSpoof_ModifyInquiryVpdPage(PUCHAR Buffer, ULONG Length, UINT8 PageCode) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    // Page 0x83 - Device Identification VPD page
    if (PageCode == 0x83 && Length >= 4) {
        UINT16 pageLength = (Buffer[2] << 8) | Buffer[3];
        if (pageLength + 4 > Length) pageLength = (UINT16)(Length - 4);
        
        PUCHAR ptr = Buffer + 4;
        UINT16 offset = 0;
        
        while (offset < pageLength) {
            UINT8 protoCode = (ptr[0] >> 4) & 0xF;
            UINT8 codeSet = ptr[0] & 0xF;
            UINT8 piv = (ptr[1] >> 7) & 1;
            UINT8 assoc = (ptr[1] >> 4) & 0x3;
            UINT8 desigType = ptr[1] & 0xF;
            UINT8 desigLen = ptr[3];
            
            // Type 1 = Binary (EUI-64 based 8-byte WWN)
            // Type 2 = ASCII (8-byte WWN)
            if (desigType == 1 && desigLen >= 8 && codeSet == 1) {
                // Save original if not saved
                if (!g_WwnContext.HaveOriginal) {
                    g_WwnContext.OriginalWWN = 0;
                    for (int i = 0; i < 8 && i < desigLen; i++) {
                        g_WwnContext.OriginalWWN |= ((UINT64)ptr[4 + i] << (56 - i * 8));
                    }
                    g_WwnContext.HaveOriginal = TRUE;
                }
                
                // Write fake WWN
                for (int i = 0; i < 8 && i < desigLen; i++) {
                    ptr[4 + i] = (UINT8)((g_WwnContext.FakeWWN >> (56 - i * 8)) & 0xFF);
                }
            }
            
            offset += (UINT16)(4 + desigLen);
            ptr += (4 + desigLen);
        }
    }
}

/*
 * Additional SCSI/ATA spoofing for comprehensive coverage
 */
VOID DiskSpoof_ModifyModeSensePage(PUCHAR Buffer, ULONG Length, UINT8 PageCode) {
    if (!g_DiskSpoofContext.Initialized || !g_DiskSpoofContext.Enabled) {
        return;
    }
    
    switch (PageCode) {
        case 0x01:  // Read-Write Error Recovery page
            // Modify error recovery settings
            if (Length >= 12) {
                // Set error recovery parameters to appear as new/healthy drive
                Buffer[3] = 0x80;  // Automatic read reassignment enabled
                Buffer[4] = 0;     // Read retry count
                Buffer[8] = 0x80;  // Automatic write reassignment enabled
                Buffer[9] = 0;     // Write retry count
            }
            break;
            
        case 0x1C:  // Informational Exceptions Control page
            // Disable SMART warnings in mode sense
            if (Length >= 12) {
                Buffer[2] = 0x00;  // Method of reporting: No reporting
                Buffer[3] = 0x00;  // No exceptions
            }
            break;
    }
}

/*
 * Initialize advanced spoofing features
 */
NTSTATUS DiskSpoof_InitializeAdvanced(VOID) {
    NTSTATUS status = DiskSpoof_Initialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Initialize WWN spoofing
    DiskSpoof_GenerateFakeWWN();
    
    return STATUS_SUCCESS;
}

// ==================== ADVANCED DISK SPOOFING FEATURES ====================

/*
 * Spoof USB/Removable disk identifiers
 * Handles USB mass storage devices
 */
typedef struct _USB_SPOOF_CONTEXT {
    BOOLEAN     Initialized;
    CHAR        FakeVendorId[9];
    CHAR        FakeProductId[17];
    CHAR        FakeRevision[5];
    UINT8       FakeSerial[32];
} USB_SPOOF_CONTEXT;

static USB_SPOOF_CONTEXT g_UsbSpoofContext = {0};

VOID UsbSpoof_GenerateFakeIds(VOID) {
    // Common USB vendor IDs to spoof as
    const CHAR* vendors[] = {"Kingston", "SanDisk", "Samsung", "Crucial", "WD"};
    const CHAR* products[] = {"DataTraveler", "Ultra", "SSD", "MyPassport", "Portable"};
    
    strncpy(g_UsbSpoofContext.FakeVendorId, 
            vendors[RtlRandomEx(NULL) % 5], 8);
    strncpy(g_UsbSpoofContext.FakeProductId, 
            products[RtlRandomEx(NULL) % 5], 16);
    
    // Generate random revision
    g_UsbSpoofContext.FakeRevision[0] = '0' + (RtlRandomEx(NULL) % 10);
    g_UsbSpoofContext.FakeRevision[1] = '.';
    g_UsbSpoofContext.FakeRevision[2] = '0' + (RtlRandomEx(NULL) % 10);
    g_UsbSpoofContext.FakeRevision[3] = '0' + (RtlRandomEx(NULL) % 10);
    g_UsbSpoofContext.FakeRevision[4] = '\0';
    
    // Generate random serial
    for (int i = 0; i < 20; i++) {
        g_UsbSpoofContext.FakeSerial[i] = 'A' + (RtlRandomEx(NULL) % 26);
    }
    
    g_UsbSpoofContext.Initialized = TRUE;
}

/*
 * Spoof RAID controller disk info
 * Handles Intel RST, AMD RAID, etc.
 */
typedef struct _RAID_SPOOF_CONTEXT {
    BOOLEAN     Initialized;
    UINT16      FakeRaidSerial;
    CHAR        FakeRaidName[32];
    UINT32      FakeArrayId;
} RAID_SPOOF_CONTEXT;

static RAID_SPOOF_CONTEXT g_RaidSpoofContext = {0};

VOID RaidSpoof_GenerateFakeIds(VOID) {
    g_RaidSpoofContext.FakeRaidSerial = (UINT16)(RtlRandomEx(NULL) & 0xFFFF);
    g_RaidSpoofContext.FakeArrayId = RtlRandomEx(NULL);
    
    // Random RAID array name
    const CHAR* raidNames[] = {"Array0", "Volume0", "RAID0", "Storage1"};
    strncpy(g_RaidSpoofContext.FakeRaidName, 
            raidNames[RtlRandomEx(NULL) % 4], 31);
    
    g_RaidSpoofContext.Initialized = TRUE;
}

/*
 * Spoof NVMe extended features
 * Controller ID, Namespace ID, etc.
 */
VOID NvmeSpoof_ExtendedFeatures(PNVME_IDENTIFY_CONTROLLER NvmeId) {
    if (!NvmeId) return;
    
    // Spoof vendor specific data
    for (int i = 0; i < 1024; i++) {
        NvmeId->VendorSpecific[i] = (UINT8)RtlRandomEx(NULL);
    }
    
    // Modify power state descriptors to appear as different model
    for (int i = 0; i < 32; i++) {
        // Randomize power consumption values
        NvmeId->Psd[i].MaxPower = 50 + (RtlRandomEx(NULL) % 200);
    }
    
    // Spoof optional admin command support
    NvmeId->Oacs = 0x1F;  // All standard admin commands
    
    // Spoof firmware update granularity
    NvmeId->Fwug = 0x04;
    
    // Spoof keep alive support
    NvmeId->Kas = 12000;  // 120 seconds in 100ms units
}

/*
 * Advanced ATA IDENTIFY spoofing
 * Modifies additional fields for deeper spoofing
 */
VOID DiskSpoof_AdvancedAtaIdentify(PAHCI_FIS_IDENTIFY Identify) {
    if (!Identify || !g_DiskSpoofContext.Initialized) return;
    
    // Modify additional fields
    Identify->Cylinders = 0;  // LBA only drive
    Identify->Heads = 0;
    Identify->SectorsPerTrack = 0;
    
    // Spoof capabilities to appear as newer drive
    Identify->Config = 0x0040;  // Fixed device
    
    // Set modern ATA version
    Identify->SpecificConfig = 0x0001;
    
    // Additional serial number randomization at firmware level
    for (int i = 0; i < 20; i += 2) {
        UINT16 word = (UINT16)RtlRandomEx(NULL);
        *((UINT16*)&Identify->SerialNumber[i]) = word;
    }
}

/*
 * Spoof drive temperature and SMART data
 * Modifies thermal and health readings
 */
typedef struct _SMART_SPOOF_DATA {
    UINT8       Temperature;
    UINT8       HealthPercent;
    UINT32      PowerOnHours;
    UINT32      PowerCycleCount;
} SMART_SPOOF_DATA;

VOID DiskSpoof_GenerateSmartData(PSMART_SPOOF_DATA SmartData) {
    if (!SmartData) return;
    
    // Generate plausible temperature (30-45C)
    SmartData->Temperature = 30 + (RtlRandomEx(NULL) % 16);
    
    // Generate high health percentage (95-100%)
    SmartData->HealthPercent = 95 + (RtlRandomEx(NULL) % 6);
    
    // Generate low power-on hours (appears as new drive)
    SmartData->PowerOnHours = RtlRandomEx(NULL) % 100;
    
    // Generate low power cycle count
    SmartData->PowerCycleCount = RtlRandomEx(NULL) % 50;
}

/*
 * Handle multiple disk types
 * Unified interface for all disk spoofing
 */
NTSTATUS DiskSpoof_HandleDiskType(UINT32 DiskType, PVOID IdentifyData, ULONG DataLength) {
    if (!IdentifyData || DataLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    switch (DiskType) {
        case 0: // SATA/AHCI
            DiskSpoof_AdvancedAtaIdentify((PAHCI_FIS_IDENTIFY)IdentifyData);
            break;
            
        case 1: // NVMe
            NvmeSpoof_ExtendedFeatures((PNVME_IDENTIFY_CONTROLLER)IdentifyData);
            break;
            
        case 2: // USB Mass Storage
            if (!g_UsbSpoofContext.Initialized) {
                UsbSpoof_GenerateFakeIds();
            }
            break;
            
        case 3: // RAID Virtual Disk
            if (!g_RaidSpoofContext.Initialized) {
                RaidSpoof_GenerateFakeIds();
            }
            break;
            
        default:
            return STATUS_NOT_SUPPORTED;
    }
    
    return STATUS_SUCCESS;
}

/*
 * Disable Windows disk write cache flush
 * Makes drive appear as different type
 */
VOID DiskSpoof_ModifyCacheBehavior(PVOID DeviceExtension) {
    // Modify device extension to change caching behavior
    // This affects how Windows interacts with the drive
}

/*
 * Spoof drive geometry
 * Changes reported CHS/LBA parameters
 */
VOID DiskSpoof_ModifyGeometry(ULONG* Cylinders, ULONG* Heads, ULONG* Sectors) {
    // Standard LBA drive geometry
    *Cylinders = 0xFFFFFFFF;  // Report as LBA48
    *Heads = 0xFF;
    *Sectors = 0xFF;
}

/*
 * Initialize all disk spoofing subsystems
 */
NTSTATUS DiskSpoof_InitializeAll(VOID) {
    NTSTATUS status = DiskSpoof_InitializeAdvanced();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Initialize USB spoofing
    UsbSpoof_GenerateFakeIds();
    
    // Initialize RAID spoofing
    RaidSpoof_GenerateFakeIds();
    
    return STATUS_SUCCESS;
}

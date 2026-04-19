/*
 * Vulnerable Driver Configurations - Predefined configs for known vulnerable drivers
 */

#include "vuln_driver_config.h"
#include <string.h>

// Intel NAL (iqvw64e.sys) - Original driver used by this spoofer
// IOCTL 0x80862007 with case-based dispatch
static VULN_DRIVER_CONFIG g_IntelNalConfig = {
    .Type = VULN_DRIVER_INTEL_NAL,
    .Name = "Intel NAL (iqvw64e.sys)",
    .DeviceName = "\\\\.\\Nal",
    .ServiceNamePrefix = "nal",
    .DriverFileName = "iqvw64e.sys",
    
    .IoctlCode = 0x80862007,
    
    // Intel NAL case numbers
    .CaseMapPhysical = 0x19,        // MapIoSpace
    .CaseUnmapPhysical = 0x1A,      // UnmapIoSpace
    .CaseCopyMemory = 0x33,         // CopyMemory (read/write)
    .CaseAllocatePool = 0x25,     // AllocatePool
    .CaseGetPhysAddr = 0x26,        // GetPhysicalAddress
    .CaseMapIoSpace = 0x19,         // Same as MapPhysical
    
    // Buffer sizes for Intel NAL
    .BufferSizeMap = 0x30,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x30,
    .BufferSizeAlloc = 0x30,
    
    // Capabilities
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = TRUE,
    
    // Constraints
    .MaxMappingSize = 0x10000000,   // 256MB max
    .AlignmentRequirement = 0x1000, // 4KB alignment
    
    // Requirements
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    // Compatibility
    .MinBuildNumber = 7600,         // Windows 7
    .MaxBuildNumber = 26000,        // Future Windows builds
    
    // Runtime status (initialized to FALSE)
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Gigabyte GDRV (gdrv.sys) - Alternative vulnerable driver
// Uses physical memory read/write via IOCTLs
static VULN_DRIVER_CONFIG g_GigabyteGdrvConfig = {
    .Type = VULN_DRIVER_GIGABYTE_GDRV,
    .Name = "Gigabyte GDRV (gdrv.sys)",
    .DeviceName = "\\\\.\\GDRV",
    .ServiceNamePrefix = "gdrv",
    .DriverFileName = "gdrv.sys",
    
    .IoctlCode = 0xC3502800,        // Custom IOCTL for GDRV
    
    // GDRV uses direct IOCTL numbers, not cases
    .CaseMapPhysical = 0,
    .CaseUnmapPhysical = 0,
    .CaseCopyMemory = 0xC3502804,   // Physical memory read/write
    .CaseAllocatePool = 0,          // Not supported
    .CaseGetPhysAddr = 0,           // Not supported
    .CaseMapIoSpace = 0,
    
    .BufferSizeMap = 0,
    .BufferSizeCopy = 0x28,
    .BufferSizeUnmap = 0,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = TRUE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x100000000,  // 4GB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = TRUE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 22000,        // Blocked on newer Windows
    
    .IsBlocklisted = TRUE,          // Known to be blocklisted
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// ASRock RGB (AsrDrv10x64.sys) - RGB controller with memory access
static VULN_DRIVER_CONFIG g_AsrockRgbConfig = {
    .Type = VULN_DRIVER_ASROCK_RGB,
    .Name = "ASRock RGB (AsrDrv10x64.sys)",
    .DeviceName = "\\\\.\\AsrDrv10",
    .ServiceNamePrefix = "asrrgb",
    .DriverFileName = "AsrDrv10x64.sys",
    
    .IoctlCode = 0x80002000,
    
    .CaseMapPhysical = 0x80002004,  // Map physical memory
    .CaseUnmapPhysical = 0x80002008, // Unmap
    .CaseCopyMemory = 0x8000200C,     // Read/Write physical
    .CaseAllocatePool = 0x80002010, // Allocate
    .CaseGetPhysAddr = 0,             // Not directly supported
    .CaseMapIoSpace = 0x80002004,
    
    .BufferSizeMap = 0x28,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x20,
    .BufferSizeAlloc = 0x28,
    
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x8000000,     // 128MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 10240,         // Windows 10
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Process Hacker (sz-ks64.sys) - Signed driver with vulnerability
static VULN_DRIVER_CONFIG g_ProcessHackerConfig = {
    .Type = VULN_DRIVER_PROCESS_HACKER,
    .Name = "Process Hacker (sz-ks64.sys)",
    .DeviceName = "\\\\.\\sz-ks64",
    .ServiceNamePrefix = "szks",
    .DriverFileName = "sz-ks64.sys",
    
    .IoctlCode = 0x80002018,
    
    .CaseMapPhysical = 0x8000201C,
    .CaseUnmapPhysical = 0x80002020,
    .CaseCopyMemory = 0x80002024,
    .CaseAllocatePool = 0x80002028,
    .CaseGetPhysAddr = 0x8000202C,
    .CaseMapIoSpace = 0x8000201C,
    
    .BufferSizeMap = 0x30,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x28,
    .BufferSizeAlloc = 0x28,
    
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = TRUE,
    
    .MaxMappingSize = 0x40000000,    // 1GB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 9200,          // Windows 8.1
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = TRUE,           // Often blocklisted
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Dell BIOS driver - Dell update utility driver
static VULN_DRIVER_CONFIG g_DellBiosConfig = {
    .Type = VULN_DRIVER_DELL_BIOS,
    .Name = "Dell BIOS Driver",
    .DeviceName = "\\\\.\\DellBios",
    .ServiceNamePrefix = "dellbios",
    .DriverFileName = "dellbios.sys",
    
    .IoctlCode = 0x222004,
    
    .CaseMapPhysical = 0x222008,
    .CaseUnmapPhysical = 0x22200C,
    .CaseCopyMemory = 0x222010,
    .CaseAllocatePool = 0,           // Not supported
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0x222008,
    
    .BufferSizeMap = 0x24,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x20,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = TRUE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x1000000,     // 16MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 10240,
    .MaxBuildNumber = 22000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// GLAZIO Intel Overclocking driver
static VULN_DRIVER_CONFIG g_GlazioConfig = {
    .Type = VULN_DRIVER_GLAZIO,
    .Name = "GLAZIO Intel Overclocking",
    .DeviceName = "\\\\.\\GLAZIO",
    .ServiceNamePrefix = "glazio",
    .DriverFileName = "GLAZIO.sys",
    
    .IoctlCode = 0x80862007,         // Similar to Intel NAL
    
    .CaseMapPhysical = 0x19,
    .CaseUnmapPhysical = 0x1A,
    .CaseCopyMemory = 0x33,
    .CaseAllocatePool = 0x25,
    .CaseGetPhysAddr = 0x26,
    .CaseMapIoSpace = 0x19,
    
    .BufferSizeMap = 0x30,
    .BufferSizeCopy = 0x30,
    .BufferSizeUnmap = 0x30,
    .BufferSizeAlloc = 0x30,
    
    .UsesMdlMapping = TRUE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = TRUE,
    .SupportsPhysicalTranslation = TRUE,
    
    .MaxMappingSize = 0x10000000,    // 256MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 10240,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Global array of all configurations
VULN_DRIVER_CONFIG g_VulnDriverConfigs[VULN_DRIVER_COUNT] = {0};

// Initialize the configuration array
static BOOL g_ConfigsInitialized = FALSE;

void InitDriverConfigs(void) {
    if (g_ConfigsInitialized) return;
    
    g_VulnDriverConfigs[VULN_DRIVER_INTEL_NAL] = g_IntelNalConfig;
    g_VulnDriverConfigs[VULN_DRIVER_GIGABYTE_GDRV] = g_GigabyteGdrvConfig;
    g_VulnDriverConfigs[VULN_DRIVER_ASROCK_RGB] = g_AsrockRgbConfig;
    g_VulnDriverConfigs[VULN_DRIVER_PROCESS_HACKER] = g_ProcessHackerConfig;
    g_VulnDriverConfigs[VULN_DRIVER_DELL_BIOS] = g_DellBiosConfig;
    g_VulnDriverConfigs[VULN_DRIVER_GLAZIO] = g_GlazioConfig;
    
    g_ConfigsInitialized = TRUE;
}

// Get configuration for a specific driver type
VULN_DRIVER_CONFIG* GetDriverConfig(VULN_DRIVER_TYPE type) {
    if (!g_ConfigsInitialized) InitDriverConfigs();
    
    if (type < 0 || type >= VULN_DRIVER_COUNT) {
        return NULL;
    }
    
    return &g_VulnDriverConfigs[type];
}

// Get driver type name
const char* GetDriverTypeName(VULN_DRIVER_TYPE type) {
    if (!g_ConfigsInitialized) InitDriverConfigs();
    
    if (type < 0 || type >= VULN_DRIVER_COUNT) {
        return "Unknown";
    }
    
    return g_VulnDriverConfigs[type].Name;
}

// Check if driver is compatible with current Windows build
BOOL IsDriverCompatible(VULN_DRIVER_CONFIG* config, ULONG currentBuild) {
    if (!config) return FALSE;
    
    if (config->MinBuildNumber > 0 && currentBuild < config->MinBuildNumber) {
        return FALSE;
    }
    
    if (config->MaxBuildNumber > 0 && currentBuild > config->MaxBuildNumber) {
        return FALSE;
    }
    
    return TRUE;
}

// Check if driver is available (not blocklisted, compatible, can be loaded)
BOOL IsDriverAvailable(VULN_DRIVER_CONFIG* config) {
    if (!config) return FALSE;
    
    // Already tested and can load
    if (config->WasTested && config->CanLoad) {
        return TRUE;
    }
    
    // Known to be blocklisted
    if (config->IsBlocklisted) {
        return FALSE;
    }
    
    // Need to check Windows version compatibility
    OSVERSIONINFOEXW osInfo = {0};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    
    typedef NTSTATUS (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo);
        if (!IsDriverCompatible(config, osInfo.dwBuildNumber)) {
            return FALSE;
        }
    }
    
    return TRUE;
}

// Convenience functions for specific drivers
VULN_DRIVER_CONFIG* GetIntelNalConfig(void) {
    return GetDriverConfig(VULN_DRIVER_INTEL_NAL);
}

VULN_DRIVER_CONFIG* GetGigabyteGdrvConfig(void) {
    return GetDriverConfig(VULN_DRIVER_GIGABYTE_GDRV);
}

VULN_DRIVER_CONFIG* GetAsrockRgbConfig(void) {
    return GetDriverConfig(VULN_DRIVER_ASROCK_RGB);
}

VULN_DRIVER_CONFIG* GetProcessHackerConfig(void) {
    return GetDriverConfig(VULN_DRIVER_PROCESS_HACKER);
}

VULN_DRIVER_CONFIG* GetDellBiosConfig(void) {
    return GetDriverConfig(VULN_DRIVER_DELL_BIOS);
}

VULN_DRIVER_CONFIG* GetGlazioConfig(void) {
    return GetDriverConfig(VULN_DRIVER_GLAZIO);
}

// ==================== ADDITIONAL VULNERABLE DRIVER CONFIGS ====================

// MSI Afterburner (RTCore64.sys) - RTCore driver with physical memory access
static VULN_DRIVER_CONFIG g_MsiAfterburnerConfig = {
    .Type = VULN_DRIVER_MSI_AFTERBURNER,
    .Name = "MSI Afterburner (RTCore64.sys)",
    .DeviceName = "\\.\\RTCore64",
    .ServiceNamePrefix = "rtcore",
    .DriverFileName = "RTCore64.sys",
    
    .IoctlCode = 0x80002048,        // RTCore physical memory IOCTL
    
    .CaseMapPhysical = 0,
    .CaseUnmapPhysical = 0,
    .CaseCopyMemory = 0x80002048,   // Direct physical memory read/write
    .CaseAllocatePool = 0,
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0,
    
    .BufferSizeMap = 0,
    .BufferSizeCopy = 0x18,
    .BufferSizeUnmap = 0,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x100000000,  // 4GB physical space
    .AlignmentRequirement = 0x1,    // Byte alignment
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// ASUS GPU Tweak (AsIO.sys) - ASUS driver with port I/O and memory access
static VULN_DRIVER_CONFIG g_AsusGpuTweakConfig = {
    .Type = VULN_DRIVER_ASUS_GPU_TWEAK,
    .Name = "ASUS GPU Tweak (AsIO.sys)",
    .DeviceName = "\\.\\AsIO",
    .ServiceNamePrefix = "asio",
    .DriverFileName = "AsIO.sys",
    
    .IoctlCode = 0xA0406440,        // ASIO IOCTL
    
    .CaseMapPhysical = 0xA0406440,  // Map physical memory
    .CaseUnmapPhysical = 0,
    .CaseCopyMemory = 0xA0406444,   // Read/Write physical memory
    .CaseAllocatePool = 0,
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0xA0406440,
    
    .BufferSizeMap = 0x18,
    .BufferSizeCopy = 0x20,
    .BufferSizeUnmap = 0,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x10000000,   // 256MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// EVGA Precision (WinRing0x64.sys) - WinRing0 driver with I/O port access
static VULN_DRIVER_CONFIG g_EvgaPrecisionConfig = {
    .Type = VULN_DRIVER_EVGA_PRECISION,
    .Name = "EVGA Precision (WinRing0x64.sys)",
    .DeviceName = "\\.\\WinRing0_1_2_0",
    .ServiceNamePrefix = "winring",
    .DriverFileName = "WinRing0x64.sys",
    
    .IoctlCode = 0x9C402580,        // WinRing0 IOCTL
    
    .CaseMapPhysical = 0x9C402588,  // Map physical memory
    .CaseUnmapPhysical = 0,
    .CaseCopyMemory = 0x9C402590,   // Read/Write physical
    .CaseAllocatePool = 0,
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0x9C402588,
    
    .BufferSizeMap = 0x10,
    .BufferSizeCopy = 0x18,
    .BufferSizeUnmap = 0,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x10000000,   // 256MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Corsair iCUE (CorsairG4Driver.sys) - Corsair driver with memory access
static VULN_DRIVER_CONFIG g_CorsairIcueConfig = {
    .Type = VULN_DRIVER_CORSAIR_ICUE,
    .Name = "Corsair iCUE (CorsairG4Driver.sys)",
    .DeviceName = "\\.\\CorsairG4",
    .ServiceNamePrefix = "corsair",
    .DriverFileName = "CorsairG4Driver.sys",
    
    .IoctlCode = 0xC3502000,        // Corsair IOCTL
    
    .CaseMapPhysical = 0,
    .CaseUnmapPhysical = 0,
    .CaseCopyMemory = 0xC3502004,   // Memory read/write
    .CaseAllocatePool = 0,
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0,
    
    .BufferSizeMap = 0,
    .BufferSizeCopy = 0x20,
    .BufferSizeUnmap = 0,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x10000000,   // 256MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// LG Kernel Driver (lgldriver.sys) - LG driver with physical memory access
static VULN_DRIVER_CONFIG g_LgDriverConfig = {
    .Type = VULN_DRIVER_LG_KERNEL,
    .Name = "LG Kernel Driver (lgldriver.sys)",
    .DeviceName = "\\.\\lgldriver",
    .ServiceNamePrefix = "lgldriver",
    .DriverFileName = "lgldriver.sys",
    
    .IoctlCode = 0x80002000,        // LG driver IOCTL
    
    .CaseMapPhysical = 0x80002004,  // Map physical memory
    .CaseUnmapPhysical = 0x80002008,
    .CaseCopyMemory = 0x8000200C,   // Read/Write physical
    .CaseAllocatePool = 0,
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0x80002004,
    
    .BufferSizeMap = 0x18,
    .BufferSizeCopy = 0x20,
    .BufferSizeUnmap = 0x10,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x10000000,   // 256MB
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Gigabyte RGB Fusion 2 (Gigabyte peripheral driver)
static VULN_DRIVER_CONFIG g_GigabyteRgb2Config = {
    .Type = VULN_DRIVER_GIGABYTE_RGB2,
    .Name = "Gigabyte RGB Fusion 2",
    .DeviceName = "\\.\\GIO",
    .ServiceNamePrefix = "giodriver",
    .DriverFileName = "giodriver.sys",
    
    .IoctlCode = 0xC3502800,
    
    .CaseMapPhysical = 0xC3502804,
    .CaseUnmapPhysical = 0,
    .CaseCopyMemory = 0xC3502808,
    .CaseAllocatePool = 0,
    .CaseGetPhysAddr = 0,
    .CaseMapIoSpace = 0xC3502804,
    
    .BufferSizeMap = 0x18,
    .BufferSizeCopy = 0x28,
    .BufferSizeUnmap = 0,
    .BufferSizeAlloc = 0,
    
    .UsesMdlMapping = FALSE,
    .RequiresPhysicalContiguous = FALSE,
    .SupportsKernelWrite = TRUE,
    .SupportsPoolAllocation = FALSE,
    .SupportsPhysicalTranslation = FALSE,
    
    .MaxMappingSize = 0x10000000,
    .AlignmentRequirement = 0x1000,
    
    .RequiresSecureBootDisabled = FALSE,
    .RequiresTestMode = FALSE,
    .RequiresDebugMode = FALSE,
    
    .MinBuildNumber = 7600,
    .MaxBuildNumber = 26000,
    
    .IsBlocklisted = FALSE,
    .WasTested = FALSE,
    .CanLoad = FALSE
};

// Accessor functions for new driver configs
VULN_DRIVER_CONFIG* GetMsiAfterburnerConfig(void) {
    return &g_MsiAfterburnerConfig;
}

VULN_DRIVER_CONFIG* GetAsusGpuTweakConfig(void) {
    return &g_AsusGpuTweakConfig;
}

VULN_DRIVER_CONFIG* GetEvgaPrecisionConfig(void) {
    return &g_EvgaPrecisionConfig;
}

VULN_DRIVER_CONFIG* GetCorsairIcueConfig(void) {
    return &g_CorsairIcueConfig;
}

VULN_DRIVER_CONFIG* GetLgDriverConfig(void) {
    return &g_LgDriverConfig;
}

VULN_DRIVER_CONFIG* GetGigabyteRgb2Config(void) {
    return &g_GigabyteRgb2Config;
}

// Update the driver configs array to include new drivers
// This would be done in the InitDriverConfigs() function

/*
 * CPUID Spoofing - Hypervisor-based CPUID Interception
 * 
 * Uses Intel VT-x/AMD-V to intercept CPUID instructions and return
 * synthetic processor identification information.
 */

#include <ntddk.h>
#include <intrin.h>

// VMX (Intel VT-x) definitions
#define VMX_BASIC_MSR           0x480
#define VMX_CR0_FIXED0_MSR      0x486
#define VMX_CR0_FIXED1_MSR      0x487
#define VMX_CR4_FIXED0_MSR      0x488
#define VMX_CR4_FIXED1_MSR      0x489
#define VMX_VMCS_ENUM_MSR       0x48A

// VMCS (Virtual Machine Control Structure) fields
#define VMCS_CTRL_PIN_BASED     0x4000
#define VMCS_CTRL_PROC_BASED    0x4002
#define VMCS_CTRL_EXIT_REASON   0x4402
#define VMCS_CTRL_ENTRY_CONTROLS 0x4012
#define VMCS_GUEST_RIP          0x681E
#define VMCS_GUEST_RFLAGS       0x6820
#define VMCS_GUEST_RSP          0x681C

// CPUID exit reason
#define EXIT_REASON_CPUID       10

// VMX instructions
#define VMX_ENABLE()            __vmx_on(&g_VmxOnRegionPhys)
#define VMX_DISABLE()           __vmx_off()
#define VMX_VMCLEAR(addr)       __vmclear(addr)
#define VMX_VMPTRLD(addr)       __vmptrld(addr)
#define VMX_VMREAD(field, val)  __vmx_vmread(field, val)
#define VMX_VMWRITE(field, val) __vmx_vmwrite(field, val)
#define VMX_VMLAUNCH()          __vmx_vmlaunch()
#define VMX_VMRESUME()          __vmx_vmresume()

// Context for CPUID spoofing
typedef struct _CPUID_SPOOF_CONTEXT {
    BOOLEAN         VmxEnabled;
    BOOLEAN         SpoofingEnabled;
    
    // VMX regions
    PVOID           VmxOnRegion;
    PHYSICAL_ADDRESS VmxOnRegionPhys;
    PVOID           VmcsRegion;
    PHYSICAL_ADDRESS VmcsRegionPhys;
    PVOID           VmmStack;
    
    // CPUID spoof values
    struct {
        UINT32  VendorEbx;
        UINT32  VendorEdx;
        UINT32  VendorEcx;
        CHAR    BrandString[48];
        UINT32  Family;
        UINT32  Model;
        UINT32  Stepping;
        UINT32  FeaturesEcx;
        UINT32  FeaturesEdx;
        UINT64  ProcessorSerial;
    } FakeCpu;
    
    // Original values
    BOOLEAN         HaveOriginal;
    struct {
        UINT32  VendorEbx;
        UINT32  VendorEdx;
        UINT32  VendorEcx;
        CHAR    BrandString[48];
        UINT32  Family;
        UINT32  Model;
        UINT32  Stepping;
        UINT32  FeaturesEcx;
        UINT32  FeaturesEdx;
    } OriginalCpu;
    
    KSPIN_LOCK      Lock;
} CPUID_SPOOF_CONTEXT;

static CPUID_SPOOF_CONTEXT g_CpuidContext = {0};

/*
 * Check if CPU supports VMX
 */
BOOLEAN CpuidSpoof_CheckVmxSupport(VOID) {
    int cpuInfo[4];
    
    // Check CPUID.1:ECX[5] for VMX support
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
        return FALSE;
    }
    
    // Check BIOS lock bit - VMX must be enabled in BIOS
    UINT64 featureControl = __readmsr(0x3A);  // IA32_FEATURE_CONTROL
    if (!(featureControl & 1)) {
        return FALSE;  // BIOS hasn't locked feature control MSR
    }
    if (!(featureControl & 4)) {
        return FALSE;  // VMX outside SMX disabled
    }
    
    return TRUE;
}

/*
 * Enable VMX operation
 */
NTSTATUS CpuidSpoof_EnableVmx(VOID) {
    if (!CpuidSpoof_CheckVmxSupport()) {
        return STATUS_NOT_SUPPORTED;
    }
    
    // Allocate VMXON region (4KB, 4KB aligned)
    g_CpuidContext.VmxOnRegion = MmAllocateContiguousMemory(
        PAGE_SIZE, 
        (PHYSICAL_ADDRESS){0, 0}
    );
    if (!g_CpuidContext.VmxOnRegion) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    g_CpuidContext.VmxOnRegionPhys = MmGetPhysicalAddress(g_CpuidContext.VmxOnRegion);
    RtlZeroMemory(g_CpuidContext.VmxOnRegion, PAGE_SIZE);
    
    // Get VMX revision identifier
    UINT64 vmxBasic = __readmsr(VMX_BASIC_MSR);
    UINT32 revision = (UINT32)vmxBasic;
    *(UINT32*)g_CpuidContext.VmxOnRegion = revision;
    
    // Set CR4.VMXE bit
    UINT64 cr4 = __readcr4();
    cr4 |= (1 << 13);  // CR4.VMXE
    __writecr4(cr4);
    
    // Set fixed bits in CR0
    UINT64 cr0Fixed0 = __readmsr(VMX_CR0_FIXED0_MSR);
    UINT64 cr0Fixed1 = __readmsr(VMX_CR0_FIXED1_MSR);
    UINT64 cr0 = __readcr0();
    cr0 |= cr0Fixed0;
    cr0 &= cr0Fixed1;
    __writecr0(cr0);
    
    // Execute VMXON
    UINT8 error = (UINT8)VMX_ENABLE();
    if (error != 0) {
        MmFreeContiguousMemory(g_CpuidContext.VmxOnRegion);
        g_CpuidContext.VmxOnRegion = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    
    g_CpuidContext.VmxEnabled = TRUE;
    return STATUS_SUCCESS;
}

/*
 * Setup VMCS (Virtual Machine Control Structure)
 */
NTSTATUS CpuidSpoof_SetupVmcs(VOID) {
    // Allocate VMCS region
    g_CpuidContext.VmcsRegion = MmAllocateContiguousMemory(
        PAGE_SIZE,
        (PHYSICAL_ADDRESS){0, 0}
    );
    if (!g_CpuidContext.VmcsRegion) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    g_CpuidContext.VmcsRegionPhys = MmGetPhysicalAddress(g_CpuidContext.VmcsRegion);
    RtlZeroMemory(g_CpuidContext.VmcsRegion, PAGE_SIZE);
    
    // Set VMCS revision
    UINT64 vmxBasic = __readmsr(VMX_BASIC_MSR);
    UINT32 revision = (UINT32)vmxBasic;
    *(UINT32*)g_CpuidContext.VmcsRegion = revision;
    
    // VMCLEAR and VMPTRLD
    VMX_VMCLEAR(&g_CpuidContext.VmcsRegionPhys);
    VMX_VMPTRLD(&g_CpuidContext.VmcsRegionPhys);
    
    // Setup VMCS fields
    // This is a minimal setup - full implementation would set up
    // guest state, host state, execution controls, etc.
    
    // Pin-based controls - enable CPUID exiting
    VMX_VMWRITE(VMCS_CTRL_PIN_BASED, 0);
    
    // Processor-based controls
    // Bit 7 = Use MSR bitmaps
    // Bit 25 = Enable CPUID exiting (CRITICAL)
    VMX_VMWRITE(VMCS_CTRL_PROC_BASED, (1 << 25));
    
    // Secondary processor-based controls
    // Would enable additional features here
    
    return STATUS_SUCCESS;
}

/*
 * CPUID exit handler
 * 
 * This is called when the guest executes CPUID
 * We modify the results before resuming guest execution
 */
VOID CpuidSpoof_HandleCpuidExit(VOID) {
    if (!g_CpuidContext.SpoofingEnabled) {
        // Let the real CPUID execute
        return;
    }
    
    // Read guest RAX (CPUID leaf)
    UINT64 guestRax, guestRbx, guestRcx, guestRdx;
    VMX_VMREAD(VMCS_GUEST_RIP, &guestRax);
    
    // CPUID leaf in RAX
    UINT32 leaf = (UINT32)guestRax;
    UINT32 subLeaf = 0;
    
    // Read RCX for sub-leaf
    // (Would need to access guest register state)
    
    UINT32 eax = 0, ebx = 0, ecx = 0, edx = 0;
    
    switch (leaf) {
        case 0x00000000:  // Vendor ID
        case 0x80000000:  // Extended vendor ID
            // Return fake vendor string
            // "GenuineIntel" -> "AuthenticAMD" or vice versa
            eax = 0x80000004;  // Max extended leaf
            ebx = g_CpuidContext.FakeCpu.VendorEbx;
            edx = g_CpuidContext.FakeCpu.VendorEdx;
            ecx = g_CpuidContext.FakeCpu.VendorEcx;
            break;
            
        case 0x00000001:  // Processor Info and Features
            // Modify family, model, stepping
            eax = (g_CpuidContext.FakeCpu.Family << 8) |
                  (g_CpuidContext.FakeCpu.Model << 4) |
                  g_CpuidContext.FakeCpu.Stepping;
            
            // Modify feature flags
            // Remove VMX bit, add AMD-V bit if spoofing as AMD
            ecx = g_CpuidContext.FakeCpu.FeaturesEcx;
            edx = g_CpuidContext.FakeCpu.FeaturesEdx;
            
            // Hide hypervisor present bit
            ecx &= ~(1 << 31);
            break;
            
        case 0x80000002:  // Brand string part 1
        case 0x80000003:  // Brand string part 2
        case 0x80000004:  // Brand string part 3
            // Return fake CPU name
            {
                INT strOffset = (leaf - 0x80000002) * 16;
                RtlCopyMemory(&eax, &g_CpuidContext.FakeCpu.BrandString[strOffset], 4);
                RtlCopyMemory(&ebx, &g_CpuidContext.FakeCpu.BrandString[strOffset + 4], 4);
                RtlCopyMemory(&ecx, &g_CpuidContext.FakeCpu.BrandString[strOffset + 8], 4);
                RtlCopyMemory(&edx, &g_CpuidContext.FakeCpu.BrandString[strOffset + 12], 4);
            }
            break;
            
        default:
            // For other leaves, execute real CPUID
            // (or could filter/modify as needed)
            int cpuInfo[4];
            __cpuidex(cpuInfo, leaf, subLeaf);
            eax = cpuInfo[0];
            ebx = cpuInfo[1];
            ecx = cpuInfo[2];
            edx = cpuInfo[3];
            break;
    }
    
    // Write modified results to guest registers
    // (Implementation depends on VMCS guest state area access)
    
    // Advance guest RIP past the CPUID instruction
    UINT64 guestRip;
    VMX_VMREAD(VMCS_GUEST_RIP, &guestRip);
    guestRip += 2;  // CPUID is 2 bytes (0F A2)
    VMX_VMWRITE(VMCS_GUEST_RIP, guestRip);
}

/*
 * VM exit handler (main entry point for all VM exits)
 */
VOID CpuidSpoof_VmExitHandler(VOID) {
    UINT64 exitReason;
    VMX_VMREAD(VMCS_CTRL_EXIT_REASON, &exitReason);
    
    exitReason &= 0xFFFF;  // Lower 16 bits contain reason
    
    switch (exitReason) {
        case EXIT_REASON_CPUID:
            CpuidSpoof_HandleCpuidExit();
            break;
            
        case 28:  // MSR read
        case 29:  // MSR write
            // Could also intercept MSR_IA32_PROCESSOR_SERIAL_NUMBER
            break;
            
        default:
            // Handle or inject to guest
            break;
    }
    
    // Resume guest execution
    VMX_VMRESUME();
}

/*
 * Initialize CPUID spoofing
 */
NTSTATUS CpuidSpoof_Initialize(VOID) {
    RtlZeroMemory(&g_CpuidContext, sizeof(g_CpuidContext));
    KeInitializeSpinLock(&g_CpuidContext.Lock);
    
    // Read original CPUID values
    int cpuInfo[4];
    
    // Vendor string
    __cpuid(cpuInfo, 0);
    g_CpuidContext.OriginalCpu.VendorEbx = cpuInfo[1];
    g_CpuidContext.OriginalCpu.VendorEdx = cpuInfo[2];
    g_CpuidContext.OriginalCpu.VendorEcx = cpuInfo[3];
    
    // Processor info
    __cpuid(cpuInfo, 1);
    g_CpuidContext.OriginalCpu.Family = ((cpuInfo[0] >> 8) & 0xF) + 
                                       ((cpuInfo[0] >> 20) & 0xFF);
    g_CpuidContext.OriginalCpu.Model = ((cpuInfo[0] >> 4) & 0xF) |
                                        (((cpuInfo[0] >> 16) & 0xF) << 4);
    g_CpuidContext.OriginalCpu.Stepping = cpuInfo[0] & 0xF;
    g_CpuidContext.OriginalCpu.FeaturesEcx = cpuInfo[2];
    g_CpuidContext.OriginalCpu.FeaturesEdx = cpuInfo[3];
    
    // Brand string
    CHAR brand[48] = {0};
    __cpuid(cpuInfo, 0x80000002);
    RtlCopyMemory(&brand[0], cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000003);
    RtlCopyMemory(&brand[16], cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000004);
    RtlCopyMemory(&brand[32], cpuInfo, 16);
    RtlCopyMemory(g_CpuidContext.OriginalCpu.BrandString, brand, 48);
    
    // Set fake CPU as AMD Ryzen (if original is Intel) or Intel (if original is AMD)
    if (RtlCompareMemory(g_CpuidContext.OriginalCpu.VendorEbx, "Genu", 4) == 4) {
        // Original is Intel, spoof as AMD
        g_CpuidContext.FakeCpu.VendorEbx = 'htuA';  // "Auth"
        g_CpuidContext.FakeCpu.VendorEdx = 'cAMD';  // "DMAc"
        g_CpuidContext.FakeCpu.VendorEcx = 'DMAc';
        g_CpuidContext.FakeCpu.Family = 0x17;  // Zen
        g_CpuidContext.FakeCpu.Model = 0x71;   // Ryzen 7
        RtlCopyMemory(g_CpuidContext.FakeCpu.BrandString,
                     "AMD Ryzen 7 3700X 8-Core Processor         ", 46);
    } else {
        // Original is AMD or other, spoof as Intel
        g_CpuidContext.FakeCpu.VendorEbx = 'uneG';
        g_CpuidContext.FakeCpu.VendorEdx = 'Ieni';
        g_CpuidContext.FakeCpu.VendorEcx = 'letn';
        g_CpuidContext.FakeCpu.Family = 6;
        g_CpuidContext.FakeCpu.Model = 0x9E;  // Coffee Lake
        RtlCopyMemory(g_CpuidContext.FakeCpu.BrandString,
                     "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz   ", 46);
    }
    
    g_CpuidContext.HaveOriginal = TRUE;
    
    return STATUS_SUCCESS;
}

/*
 * Install CPUID hook via hypervisor
 */
NTSTATUS CpuidSpoof_InstallHook(VOID) {
    NTSTATUS status = CpuidSpoof_Initialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = CpuidSpoof_EnableVmx();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = CpuidSpoof_SetupVmcs();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Setup VMM stack
    g_CpuidContext.VmmStack = ExAllocatePoolWithTag(
        NonPagedPool,
        PAGE_SIZE,
        'CPUI'
    );
    if (!g_CpuidContext.VmmStack) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Enable spoofing
    g_CpuidContext.SpoofingEnabled = TRUE;
    
    // VMLAUNCH would happen here to enter VMX non-root mode
    // This requires setting up host state, guest state, etc.
    
    return STATUS_SUCCESS;
}

/*
 * Remove CPUID hook
 */
VOID CpuidSpoof_RemoveHook(VOID) {
    g_CpuidContext.SpoofingEnabled = FALSE;
    
    if (g_CpuidContext.VmxEnabled) {
        VMX_DISABLE();
        g_CpuidContext.VmxEnabled = FALSE;
    }
    
    if (g_CpuidContext.VmcsRegion) {
        MmFreeContiguousMemory(g_CpuidContext.VmcsRegion);
        g_CpuidContext.VmcsRegion = NULL;
    }
    
    if (g_CpuidContext.VmxOnRegion) {
        MmFreeContiguousMemory(g_CpuidContext.VmxOnRegion);
        g_CpuidContext.VmxOnRegion = NULL;
    }
    
    if (g_CpuidContext.VmmStack) {
        ExFreePoolWithTag(g_CpuidContext.VmmStack, 'CPUI');
        g_CpuidContext.VmmStack = NULL;
    }
}

/*
 * Enable/disable spoofing
 */
VOID CpuidSpoof_Enable(BOOLEAN Enable) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CpuidContext.Lock, &oldIrql);
    g_CpuidContext.SpoofingEnabled = Enable;
    KeReleaseSpinLock(&g_CpuidContext.Lock, oldIrql);
}

// ==================== ADVANCED CPUID SPOOFING ====================

/*
 * Advanced CPU feature spoofing
 * Modifies reported CPU features to mask virtual machine traces
 */
typedef struct _CPU_FEATURE_MASK {
    // Leaf 1 ECX features
    BOOLEAN HideVMX;           // Bit 5 - Intel VMX
    BOOLEAN HideHypervisor;    // Bit 31 - Hypervisor present
    
    // Leaf 1 EDX features  
    BOOLEAN HideMTRR;          // Bit 12 - Memory Type Range Registers
    BOOLEAN HidePAT;           // Bit 16 - Page Attribute Table
    
    // Leaf 7 EBX features (Extended Features)
    BOOLEAN HideSGX;           // Bit 2 - Software Guard Extensions
    BOOLEAN HideHLE;           // Bit 4 - Hardware Lock Elision
    BOOLEAN HideRTM;           // Bit 11 - Restricted Transactional Memory
    BOOLEAN HideMPX;           // Bit 14 - Memory Protection Extensions
    
    // Leaf 7 ECX features
    BOOLEAN HidePREFETCHWT1;   // Bit 0 - PREFETCHWT1
    BOOLEAN HidePKU;           // Bit 3 - Protection Keys for Userspace
    BOOLEAN HideCET;           // Bit 7 - Control-flow Enforcement Technology
} CPU_FEATURE_MASK;

static CPU_FEATURE_MASK g_FeatureMask = {0};

/*
 * Apply feature masking to CPUID results
 * Call this from CPUID exit handler
 */
VOID CpuidSpoof_ApplyFeatureMask(PCPUID_RESULT Result) {
    if (!g_CpuidContext.SpoofingEnabled) return;
    
    switch (Result->Leaf) {
        case 1:
            // Mask out VMX and hypervisor bits
            if (g_FeatureMask.HideVMX) {
                Result->Ecx &= ~(1 << 5);
            }
            if (g_FeatureMask.HideHypervisor) {
                Result->Ecx &= ~(1 << 31);
            }
            if (g_FeatureMask.HideMTRR) {
                Result->Edx &= ~(1 << 12);
            }
            if (g_FeatureMask.HidePAT) {
                Result->Edx &= ~(1 << 16);
            }
            break;
            
        case 7:
            // Extended features
            if (g_FeatureMask.HideSGX) {
                Result->Ebx &= ~(1 << 2);
            }
            if (g_FeatureMask.HideHLE) {
                Result->Ebx &= ~(1 << 4);
            }
            if (g_FeatureMask.HideRTM) {
                Result->Ebx &= ~(1 << 11);
            }
            if (g_FeatureMask.HideMPX) {
                Result->Ebx &= ~(1 << 14);
            }
            if (g_FeatureMask.HidePKU) {
                Result->Ecx &= ~(1 << 3);
            }
            if (g_FeatureMask.HideCET) {
                Result->Ecx &= ~(1 << 7);
            }
            break;
    }
}

/*
 * Set feature mask for anti-detection
 */
VOID CpuidSpoof_SetFeatureMask(PCPU_FEATURE_MASK Mask) {
    if (!Mask) return;
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CpuidContext.Lock, &oldIrql);
    RtlCopyMemory(&g_FeatureMask, Mask, sizeof(CPU_FEATURE_MASK));
    KeReleaseSpinLock(&g_CpuidContext.Lock, oldIrql);
}

/*
 * Generate consistent but fake processor serial number
 * Used for PSN (Processor Serial Number) leaf
 */
VOID CpuidSpoof_GenerateFakePSN(UINT32* PsnHigh, UINT32* PsnLow) {
    // Generate deterministic but different serial
    UINT32 seed = (UINT32)__rdtsc();
    *PsnHigh = RtlRandomEx(&seed);
    *PsnLow = RtlRandomEx(&seed);
}

/*
 * Spoof brand string with fake processor name
 */
VOID CpuidSpoof_SetFakeBrandString(const CHAR* BrandString) {
    if (!BrandString) return;
    
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CpuidContext.Lock, &oldIrql);
    
    // Parse brand string into 3 leaves (80000002h-80000004h)
    // Each leaf returns 16 bytes in EAX:EBX:ECX:EDX
    size_t len = strlen(BrandString);
    
    for (int i = 0; i < 3 && i * 16 < len; i++) {
        UINT32* dest = (UINT32*)g_CpuidContext.FakeBrand[i * 4];
        const CHAR* src = BrandString + (i * 16);
        
        for (int j = 0; j < 4 && (i * 16 + j * 4) < len; j++) {
            dest[j] = (src[j*4]) | (src[j*4+1] << 8) | 
                      (src[j*4+2] << 16) | (src[j*4+3] << 24);
        }
    }
    
    KeReleaseSpinLock(&g_CpuidContext.Lock, oldIrql);
}

/*
 * Spoof cache and TLB info
 * Leaf 2 (descriptors) and leaf 4 (deterministic cache)
 */
VOID CpuidSpoof_ModifyCacheInfo(PCPUID_RESULT Result) {
    if (!g_CpuidContext.SpoofingEnabled) return;
    
    switch (Result->Leaf) {
        case 2: // Cache descriptors
            // Report different cache configuration
            // 0x4A = 0x01 for data TLB, 0x02 for instruction TLB
            Result->Eax = 0x01;
            Result->Ebx = 0x02;
            Result->Ecx = 0x03;
            Result->Edx = 0x00;
            break;
            
        case 4: // Deterministic cache parameters
            // Modify cache size and associativity
            if (Result->SubLeaf == 0) { // L1 Data
                Result->Eax = (1 << 5) | (7 << 14); // 32 sets, 8-way
                Result->Ebx = (63 << 0) | (7 << 22); // 64 line size, 8 partitions
                Result->Ecx = 32; // 32KB
            } else if (Result->SubLeaf == 1) { // L1 Instruction
                Result->Eax = (1 << 5) | (7 << 14);
                Result->Ebx = (63 << 0) | (7 << 22);
                Result->Ecx = 32;
            } else if (Result->SubLeaf == 2) { // L2
                Result->Eax = (1 << 5) | (15 << 14);
                Result->Ebx = (63 << 0) | (3 << 22);
                Result->Ecx = 256; // 256KB
            }
            break;
    }
}

/*
 * Spoof APIC (Advanced Programmable Interrupt Controller) ID
 * Leaf 1 EBX bits 31-24
 */
VOID CpuidSpoof_SetFakeApicId(UINT8 ApicId) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_CpuidContext.Lock, &oldIrql);
    
    // Modify leaf 1 EBX to report different APIC ID
    UINT32 ebx = g_CpuidContext.FakeValues[1].Ebx;
    ebx = (ebx & 0x00FFFFFF) | (ApicId << 24);
    g_CpuidContext.FakeValues[1].Ebx = ebx;
    
    KeReleaseSpinLock(&g_CpuidContext.Lock, oldIrql);
}

/*
 * Spoof performance monitoring info
 * Leaf 0Ah
 */
VOID CpuidSpoof_ModifyPerfMonInfo(PCPUID_RESULT Result) {
    if (!g_CpuidContext.SpoofingEnabled) return;
    if (Result->Leaf != 0x0A) return;
    
    // Report different performance monitoring capabilities
    Result->Eax = 0x00040004; // 4 counters, 4 fixed counters
    Result->Ebx = 0x00000007; // Counter bit width
    Result->Ecx = 0x00000000; // Reserved
    Result->Edx = 0x0000030F; // Fixed counter bit width, events
}

/*
 * Spoof extended topology info
 * Leaf 0Bh/1Fh
 */
VOID CpuidSpoof_ModifyTopologyInfo(PCPUID_RESULT Result) {
    if (!g_CpuidContext.SpoofingEnabled) return;
    if (Result->Leaf != 0x0B && Result->Leaf != 0x1F) return;
    
    // Report different topology (single socket, fewer cores)
    Result->Ecx = Result->SubLeaf; // Level type
    Result->Edx = Result->SubLeaf; // x2APIC ID
    
    switch (Result->SubLeaf) {
        case 0: // SMT level
            Result->Eax = 0; // Number of bits shift
            Result->Ebx = 1; // Number of logical processors
            break;
        case 1: // Core level
            Result->Eax = 1;
            Result->Ebx = 4; // Report 4 cores
            break;
    }
}

/*
 * Detect and spoof based on CPU vendor
 * AMD vs Intel have different CPUID layouts
 */
typedef enum _CPU_VENDOR {
    CPU_VENDOR_INTEL,
    CPU_VENDOR_AMD,
    CPU_VENDOR_UNKNOWN
} CPU_VENDOR;

CPU_VENDOR CpuidSpoof_DetectVendor(VOID) {
    CPUID_RESULT result;
    __cpuid((int*)&result, 0);
    
    // Check EBX-EDX-ECX signature
    if (result.Ebx == 'uneG' && result.Edx == 'ineI' && result.Ecx == 'letn') {
        return CPU_VENDOR_INTEL;
    }
    if (result.Ebx == 'htuA' && result.Edx == 'itne' && result.Ecx == 'DMAc') {
        return CPU_VENDOR_AMD;
    }
    
    return CPU_VENDOR_UNKNOWN;
}

/*
 * AMD-specific spoofing
 * Different leaves and feature bits
 */
VOID CpuidSpoof_ApplyAmdSpoofing(PCPUID_RESULT Result) {
    if (CpuidSpoof_DetectVendor() != CPU_VENDOR_AMD) return;
    
    switch (Result->Leaf) {
        case 0x80000001: // Extended processor info
            // Mask out SVM (Secure Virtual Machine) bit if hiding hypervisor
            if (g_FeatureMask.HideHypervisor) {
                Result->Ecx &= ~(1 << 2); // SVM bit
            }
            break;
            
        case 0x80000008: // Virtual/Physical address size
            // Modify reported address sizes
            Result->Eax = (48 << 0) | (48 << 8); // 48-bit virtual/physical
            break;
            
        case 0x8000001E: // Node, core, thread identifiers
            // Spoof node topology
            Result->Eax = 0; // Node ID
            Result->Ebx = (1 << 8) | 4; // 4 cores per node
            break;
    }
}

/*
 * Initialize advanced CPUID spoofing
 */
NTSTATUS CpuidSpoof_InitializeAdvanced(VOID) {
    NTSTATUS status = CpuidSpoof_Initialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Set default feature mask (hide VM indicators)
    CPU_FEATURE_MASK mask = {0};
    mask.HideVMX = TRUE;
    mask.HideHypervisor = TRUE;
    CpuidSpoof_SetFeatureMask(&mask);
    
    // Set plausible brand string
    const CHAR* fakeBrand = "Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz";
    CpuidSpoof_SetFakeBrandString(fakeBrand);
    
    return STATUS_SUCCESS;
}

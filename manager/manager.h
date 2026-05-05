/*
 * HWID Spoofer - Manager Main Header
 * 
 * This header declares all global variables and function prototypes
 * used across the modular manager components.
 */

#ifndef MANAGER_H
#define MANAGER_H

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <commctrl.h>
#include <ipifcons.h>

#include "resource.h"
#include "trace_cleaner.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#pragma comment(linker,""/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\""")

// ==================== KDMAPPER CONFIGURATION ====================

#define IOCTL_NAL_MAP      0x80862007

// ==================== RESOURCE IDS ====================

#ifndef IDR_VULN_SYS
#define IDR_VULN_SYS       100
#endif
#ifndef IDR_SPOOFER_SYS
#define IDR_SPOOFER_SYS    101
#endif

// ==================== COLORS - HEX SPOOFER THEME ====================

#define CLR_BG           RGB(10, 10, 14)
#define CLR_PANEL        RGB(18, 18, 26)
#define CLR_BORDER       RGB(40, 40, 55)
#define CLR_TEXT         RGB(230, 230, 240)
#define CLR_TEXT_DIM     RGB(130, 130, 150)
#define CLR_ACCENT       RGB(236, 72, 153)  // Pink/Magenta accent
#define CLR_ACCENT_SEC   RGB(139, 92, 246)  // Purple accent
#define CLR_GREEN        RGB(34, 197, 94)
#define CLR_RED          RGB(239, 68, 68)
#define CLR_ORANGE       RGB(245, 158, 11)
#define CLR_BTN_MAIN     RGB(236, 72, 153)   // Pink main button
#define CLR_BTN_MAIN_H   RGB(251, 113, 133) // Pink hover
#define CLR_BTN_SPOOF    RGB(139, 92, 246)   // Purple spoof button  
#define CLR_BTN_SPOOF_H  RGB(167, 139, 250) // Purple hover
#define CLR_WHITE        RGB(255, 255, 255)
#define CLR_CHECKBOX     RGB(236, 72, 153)  // Checkbox color
#define CLR_SECTION_BG   RGB(22, 22, 32)    // Section background

// ==================== CONTROL IDS ====================

// WiFi Functions
#define IDC_CHK_FLUSH_DNS    1001
#define IDC_CHK_TCP_RESET    1002
#define IDC_CHK_WIFI_RESET   1003

// File Functions  
#define IDC_CHK_TEMP_FILES   1004
#define IDC_CHK_WIN_TEMP     1005
#define IDC_CHK_WIN_LOGS     1006

// Browser Functions
#define IDC_CHK_CHROME_COOK  1007
#define IDC_CHK_FIREFOX_COOK 1008

// Anti-Cheat
#define IDC_CHK_ANTICHEAT_TRACE 1009
#define IDC_CHK_FORTNITE     1010
#define IDC_CHK_FIVEM        1011
#define IDC_CHK_VALORANT     1012

// Unlink Functions
#define IDC_CHK_UNLINK_XBOX  1013
#define IDC_CHK_UNLINK_DISCORD 1014

// Action Buttons
#define IDC_BTN_START_CLEAN  1100
#define IDC_BTN_SPOOF_ALL    1101

// Old IDs for compatibility
#define IDC_BTN_CHANGE       1001
#define IDC_BTN_REVERT       1002
#define IDC_COMBO_DURATION   1003
#define IDC_BTN_REFRESH      1004
#define IDC_BTN_CLEAN_TRACES 1005
#define IDT_DURATION_TIMER   2001
#define IDT_COUNTDOWN_TIMER  2002

// ==================== DURATION OPTIONS ====================

#define DUR_1_DAY       0
#define DUR_7_DAYS      1
#define DUR_30_DAYS     2
#define DUR_UNTIL_REBOOT 3

// ==================== GLOBAL VARIABLES ====================

extern HINSTANCE g_hInst;
extern HWND g_hWnd;
extern HWND g_hBtnChange, g_hBtnRevert, g_hComboDuration, g_hBtnRefresh, g_hBtnCleanTraces;
extern HFONT g_hFontTitle, g_hFontNormal, g_hFontSmall, g_hFontBold, g_hFontMono;
extern HBRUSH g_hBrBg, g_hBrPanel, g_hBrBorder;

extern BOOL g_SpooferLoaded;
extern CHAR g_OriginalDiskSerial[256];
extern UCHAR g_OriginalMAC[6];
extern BOOL g_OriginalMACValid;
extern CHAR g_CurrentDiskSerial[256];
extern UCHAR g_CurrentMAC[6];
extern BOOL g_CurrentMACValid;

extern CHAR g_OrigBIOSSerial[256];
extern CHAR g_OrigBoardSerial[256];
extern CHAR g_OrigSystemUUID[256];
extern ULONG g_OrigVolumeSerial;
extern BOOL g_OrigVolumeSerialValid;
extern CHAR g_OrigGPUID[256];

extern CHAR g_CurrBIOSSerial[256];
extern CHAR g_CurrBoardSerial[256];
extern CHAR g_CurrSystemUUID[256];
extern ULONG g_CurrVolumeSerial;
extern BOOL g_CurrVolumeSerialValid;
extern CHAR g_CurrGPUID[256];

extern CHAR g_StatusText[256];
extern COLORREF g_StatusColor;
extern ULONGLONG g_SpoofExpiry;
extern int g_SelectedDuration;
extern CHAR g_TimeRemaining[64];

extern BOOL g_HoverChange;
extern BOOL g_HoverRevert;
extern BOOL g_HoverCleanTraces;

// Checkbox states for Hex GUI
extern BOOL g_ChkFlushDNS;
extern BOOL g_ChkTCPReset;
extern BOOL g_ChkWiFiReset;
extern BOOL g_ChkTempFiles;
extern BOOL g_ChkWinTemp;
extern BOOL g_ChkWinLogs;
extern BOOL g_ChkChromeCookies;
extern BOOL g_ChkFirefoxCookies;
extern BOOL g_ChkAntiCheatTrace;
extern BOOL g_ChkFortnite;
extern BOOL g_ChkFiveM;
extern BOOL g_ChkValorant;
extern BOOL g_ChkUnlinkXbox;
extern BOOL g_ChkUnlinkDiscord;

// Button hover states
extern BOOL g_HoverStartClean;
extern BOOL g_HoverSpoofAll;
extern int g_HoverCheckbox;

// Extended ID tracking (from driver log)
#pragma pack(push, 1)
typedef struct {
    CHAR Magic[8];
    CHAR OrigDiskSerial[64];
    CHAR FakeDiskSerial[64];
    CHAR OrigBIOSSerial[64];
    CHAR FakeBIOSSerial[64];
    CHAR OrigBoardSerial[64];
    CHAR FakeBoardSerial[64];
    CHAR OrigSystemUUID[48];
    CHAR FakeSystemUUID[48];
    UCHAR OrigMAC[6];
    UCHAR FakeMAC[6];
    ULONG OrigVolumeSerial[1];
    ULONG FakeVolumeSerial[1];
    CHAR OrigGPUId[64];
    CHAR FakeGPUId[64];
    CHAR OrigModelNumber[48];
    CHAR FakeModelNumber[48];
    CHAR OrigFirmwareRev[16];
    CHAR FakeFirmwareRev[16];
    CHAR OrigSmbBoardSerial[64];
} HWID_LOG;
#pragma pack(pop)

extern HWID_LOG g_HwidLog;
extern BOOL g_LogLoaded;

extern CHAR g_TempDir[MAX_PATH];
extern CHAR g_VulnDriverPath[MAX_PATH];
extern CHAR g_VulnServiceName[32];
extern CHAR g_VulnDeviceName[64];

extern HANDLE g_hVulnDriver;
extern PVOID g_KernelBase;

extern char g_LastMapFail[512];

// ==================== FUNCTION PROTOTYPES ====================

// GUI Functions (GUI/gui_*.c)
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void InitFonts(void);
void DestroyFonts(void);
void DrawPanel(HDC hdc, RECT* rc, const char* title);
void DrawTextLine(HDC hdc, int x, int y, const char* label, const char* value, COLORREF valColor);
void DrawButton(HDC hdc, RECT* rc, const char* text, COLORREF bgColor, BOOL hover);
void DrawSection(HDC hdc, int x, int y, int w, int h, const char* title);
void DrawCheckbox(HDC hdc, int x, int y, int size, BOOL checked, BOOL hovered, const char* label, int labelX);
void DrawHexButton(HDC hdc, RECT* rc, const char* text, COLORREF bgColor, BOOL hover);

// HWID Functions (HWID/hwid_*.c)
void ReadAllHWIDs(void);
BOOL GetDiskSerial(char* buffer, size_t bufferSize);
BOOL GetMACAddress(UCHAR* mac);
BOOL GetBIOSSerial(char* buffer, size_t bufferSize);
BOOL GetBoardSerial(char* buffer, size_t bufferSize);
BOOL GetSystemUUID(char* buffer, size_t bufferSize);
BOOL GetVolumeSerialNum(ULONG* serial);
BOOL GetGPUID(char* buffer, size_t bufferSize);
void RefreshCurrentHWIDs(void);

// Core Spoofing Functions (Core/core_*.c)
void DoSpoofHWID(void);
void DoRevertHWID(void);
void DoCleanTraces(void);
void DoStartCleaning(void);
void DoSpoofAll(void);
void UpdateStatus(void);
static void SignalDriverRevert(void);

// Driver/KDMapper Functions (Driver/driver_*.c)
BOOL LoadVulnerableDriver(void);
VOID UnloadVulnerableDriver(void);
PVOID KM_GetKernelBase(void);
PVOID KM_MapPhysicalMemory(ULONG64 physAddr, SIZE_T size);
VOID KM_UnmapPhysicalMemory(PVOID virtAddr, SIZE_T size);
BOOL KM_CopyKernelMemory(ULONG64 dest, ULONG64 src, SIZE_T size);
BOOL KM_ReadKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
BOOL KM_WriteKernelMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
BOOL KM_ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size);
BOOL KM_WritePhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size);
ULONG64 KM_TranslateLinearAddress(ULONG64 dirBase, ULONG64 virtualAddr);
ULONG64 KM_GetDirectoryTableBase(void);
BOOL KM_WriteToReadOnlyMemory(ULONG64 kernelAddr, PVOID buffer, SIZE_T size);
PVOID KM_GetKernelExport(const char* name);
BOOL KM_ProcessRelocations(PVOID imageBase, PVOID mappedBase, SIZE_T imageSize);
BOOL KM_ResolveImports(PVOID imageBase);
ULONG64 KM_FindCodeCave(SIZE_T needed);
ULONG64 KM_AllocateKernelPool(SIZE_T size);
BOOL KM_CallDriverEntry(ULONG64 entryAddr);
BOOL KM_MapDriverFromMemory(PVOID buffer, DWORD size);
BOOL LoadSpooferDriver(void);
BOOL UnloadSpooferDriver(void);

// Utility Functions (Utils/utils_*.c)
BOOL CreateHiddenTempDirectory(void);
BOOL ExtractResource(int resourceId, const char* outputPath);
BOOL ExtractDriverFiles(void);
void SecureWipeFile(const char* path);
void CleanupTempFiles(void);
void GenerateRandomHexName(char* buffer, size_t len);
BOOL IsAdmin(void);
void DbgLog(const char* fmt, ...);
void SetLastMapFailV(const char* fmt, ...);
void ClearLastMapFail(void);
BOOL ReadHwidLog(void);
void SaveHwidLogToDocuments(void);
BOOL KM_AllowUnsafeKernelVaProbe(void);

#endif // MANAGER_H

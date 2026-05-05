/*
 * HWID Spoofer - Global Variables Definitions
 * 
 * This file defines all global variables declared in manager.h
 */

#include "manager.h"

// ==================== GUI GLOBALS ====================

HINSTANCE g_hInst = NULL;
HWND g_hWnd = NULL;
HWND g_hBtnChange = NULL, g_hBtnRevert = NULL, g_hComboDuration = NULL, 
     g_hBtnRefresh = NULL, g_hBtnCleanTraces = NULL;
HFONT g_hFontTitle = NULL, g_hFontNormal = NULL, g_hFontSmall = NULL, 
      g_hFontBold = NULL, g_hFontMono = NULL;
HBRUSH g_hBrBg = NULL, g_hBrPanel = NULL, g_hBrBorder = NULL;

// ==================== HWID GLOBALS ====================

BOOL g_SpooferLoaded = FALSE;
CHAR g_OriginalDiskSerial[256] = "(unknown)";
UCHAR g_OriginalMAC[6] = {0};
BOOL g_OriginalMACValid = FALSE;
CHAR g_CurrentDiskSerial[256] = "(unknown)";
UCHAR g_CurrentMAC[6] = {0};
BOOL g_CurrentMACValid = FALSE;

CHAR g_OrigBIOSSerial[256] = "(unknown)";
CHAR g_OrigBoardSerial[256] = "(unknown)";
CHAR g_OrigSystemUUID[256] = "(unknown)";
ULONG g_OrigVolumeSerial = 0;
BOOL g_OrigVolumeSerialValid = FALSE;
CHAR g_OrigGPUID[256] = "(unknown)";

CHAR g_CurrBIOSSerial[256] = "(unknown)";
CHAR g_CurrBoardSerial[256] = "(unknown)";
CHAR g_CurrSystemUUID[256] = "(unknown)";
ULONG g_CurrVolumeSerial = 0;
BOOL g_CurrVolumeSerialValid = FALSE;
CHAR g_CurrGPUID[256] = "(unknown)";

CHAR g_StatusText[256] = "INACTIVE";
COLORREF g_StatusColor = CLR_RED;

ULONGLONG g_SpoofExpiry = 0;
int g_SelectedDuration = DUR_UNTIL_REBOOT;
CHAR g_TimeRemaining[64] = "";

// ==================== HOVER STATES ====================

BOOL g_HoverChange = FALSE;
BOOL g_HoverRevert = FALSE;
BOOL g_HoverCleanTraces = FALSE;

// ==================== CHECKBOX STATES ====================

BOOL g_ChkFlushDNS = FALSE;
BOOL g_ChkTCPReset = FALSE;
BOOL g_ChkWiFiReset = FALSE;
BOOL g_ChkTempFiles = TRUE;
BOOL g_ChkWinTemp = TRUE;
BOOL g_ChkWinLogs = TRUE;
BOOL g_ChkChromeCookies = TRUE;
BOOL g_ChkFirefoxCookies = TRUE;
BOOL g_ChkAntiCheatTrace = FALSE;
BOOL g_ChkFortnite = FALSE;
BOOL g_ChkFiveM = FALSE;
BOOL g_ChkValorant = FALSE;
BOOL g_ChkUnlinkXbox = FALSE;
BOOL g_ChkUnlinkDiscord = FALSE;

BOOL g_HoverStartClean = FALSE;
BOOL g_HoverSpoofAll = FALSE;
int g_HoverCheckbox = -1;

// ==================== DRIVER GLOBALS ====================

HWID_LOG g_HwidLog = {0};
BOOL g_LogLoaded = FALSE;

CHAR g_TempDir[MAX_PATH] = {0};
CHAR g_VulnDriverPath[MAX_PATH] = {0};
CHAR g_VulnServiceName[32] = {0};
CHAR g_VulnDeviceName[64] = {0};

HANDLE g_hVulnDriver = INVALID_HANDLE_VALUE;
PVOID g_KernelBase = NULL;

char g_LastMapFail[512] = {0};

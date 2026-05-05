/*
 * GUI Main Window Header
 * HWID Spoofer - Main Window Procedure and GUI Management
 */

#ifndef GUI_MAIN_H
#define GUI_MAIN_H

#include <windows.h>
#include "gui_colors.h"
#include "gui_ids.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==================== GLOBAL WINDOW HANDLES ====================

extern HWND g_hWnd;
extern HINSTANCE g_hInst;

// Control handles
extern HWND g_hBtnChange;
extern HWND g_hBtnRevert;
extern HWND g_hComboDuration;
extern HWND g_hBtnRefresh;
extern HWND g_hBtnCleanTraces;

// ==================== WINDOW FUNCTIONS ====================

// Register window class
BOOL GUI_RegisterClass(HINSTANCE hInstance);

// Create main window
HWND GUI_CreateMainWindow(HINSTANCE hInstance);

// Window procedure
LRESULT CALLBACK GUI_WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ==================== GUI UPDATES ====================

// Refresh the window display
void GUI_Invalidate(void);

// Update status text
void GUI_SetStatus(const char* text, COLORREF color);

// Update HWID display
void GUI_UpdateHWIDDisplay(void);

// ==================== HOVER TRACKING ====================

// Checkbox hover state
extern int g_HoverCheckbox;

// Button hover states
extern BOOL g_HoverChange;
extern BOOL g_HoverRevert;
extern BOOL g_HoverCleanTraces;
extern BOOL g_HoverRefresh;

// Checkbox states (for new GUI)
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

#ifdef __cplusplus
}
#endif

#endif // GUI_MAIN_H

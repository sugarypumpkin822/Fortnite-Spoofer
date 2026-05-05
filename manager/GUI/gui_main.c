/*
 * GUI Main Window Implementation
 * HWID Spoofer - Main Window Procedure and GUI Management
 */

#include "gui_main.h"
#include "gui_draw.h"
#include <stdio.h>
#include <string.h>

// ==================== WINDOW CLASS ====================

#define WINDOW_CLASS_NAME "HWIDSpooferMainWindow"
#define WINDOW_TITLE      "HWID Spoofer"

BOOL GUI_RegisterClass(HINSTANCE hInstance) {
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = GUI_WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = WINDOW_CLASS_NAME;
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    
    return RegisterClassExA(&wc) != 0;
}

HWND GUI_CreateMainWindow(HINSTANCE hInstance) {
    g_hInst = hInstance;
    
    HWND hWnd = CreateWindowExA(
        0,
        WINDOW_CLASS_NAME,
        WINDOW_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 650,
        NULL, NULL,
        hInstance,
        NULL
    );
    
    if (hWnd) {
        g_hWnd = hWnd;
        
        // Center window
        RECT rc;
        GetWindowRect(hWnd, &rc);
        int x = (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2;
        int y = (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2;
        SetWindowPos(hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }
    
    return hWnd;
}

// ==================== WINDOW PROCEDURE ====================

// Forward declarations for external functions (from manager.c)
extern void DoSpoofHWID(void);
extern void DoRevertHWID(void);
extern void RefreshCurrentHWIDs(void);
extern void DoCleanTraces(void);
extern int ReadAllHWIDs(void);
extern BOOL CreateHiddenTempDirectory(void);

// Duration options
#define DUR_1_DAY        0
#define DUR_7_DAYS       1
#define DUR_30_DAYS      2
#define DUR_UNTIL_REBOOT 3

// Spoofer state (from manager.c)
extern BOOL g_SpooferLoaded;
extern CHAR g_StatusText[256];
extern COLORREF g_StatusColor;
extern time_t g_SpoofExpiry;

LRESULT CALLBACK GUI_WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Initialize brushes
        g_hBrBg = CreateSolidBrush(CLR_BG);
        g_hBrPanel = CreateSolidBrush(CLR_PANEL);
        g_hBrBorder = CreateSolidBrush(CLR_BORDER);
        
        // Initialize fonts
        InitFonts();
        
        // Create duration combo
        g_hComboDuration = CreateWindowExA(0, "COMBOBOX", NULL,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
            290, 728, 190, 200, hWnd, (HMENU)IDC_COMBO_DURATION, g_hInst, NULL);
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"1 Day");
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"7 Days");
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"30 Days");
        SendMessageA(g_hComboDuration, CB_ADDSTRING, 0, (LPARAM)"Until Reboot");
        SendMessageA(g_hComboDuration, CB_SETCURSEL, DUR_UNTIL_REBOOT, 0);
        SendMessageA(g_hComboDuration, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
        
        // Read HWIDs on startup
        ReadAllHWIDs();
        
        // Create temp directory
        if (!CreateHiddenTempDirectory()) {
            MessageBoxA(hWnd, "Failed to create temp directory.", "Error", MB_ICONERROR);
        }
        
        // Set up timer
        SetTimer(hWnd, IDT_COUNTDOWN_TIMER, 1000, NULL);
        
        return 0;
    }
    
    case WM_TIMER: {
        if (wParam == IDT_COUNTDOWN_TIMER) {
            if (g_SpooferLoaded && g_SpoofExpiry > 0) {
                time_t now = time(NULL);
                if (now >= g_SpoofExpiry) {
                    // Auto revert
                    DoRevertHWID();
                    InvalidateRect(hWnd, NULL, TRUE);
                } else {
                    // Update display
                    InvalidateRect(hWnd, NULL, FALSE);
                }
            }
        }
        return 0;
    }
    
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        
        RECT clientRect;
        GetClientRect(hWnd, &clientRect);
        
        // Create memory DC for double buffering
        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
        SelectObject(memDC, memBmp);
        
        // Fill background
        FillRect(memDC, &clientRect, g_hBrBg);
        
        // Draw title
        SelectObject(memDC, g_hFontTitle);
        SetTextColor(memDC, CLR_ACCENT);
        SetBkMode(memDC, TRANSPARENT);
        TextOutA(memDC, 20, 15, "HWID SPOOFER", 12);
        
        // Draw status section
        RECT rcStatus = {20, 55, 880, 90};
        DrawPanel(memDC, &rcStatus, NULL);
        
        SelectObject(memDC, g_hFontBold);
        SetTextColor(memDC, g_StatusColor);
        DrawTextA(memDC, g_StatusText, -1, &rcStatus, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        // Blit to screen
        BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, memDC, 0, 0, SRCCOPY);
        
        DeleteObject(memBmp);
        DeleteDC(memDC);
        EndPaint(hWnd, &ps);
        return 0;
    }
    
    case WM_LBUTTONDOWN: {
        int mx = LOWORD(lParam);
        int my = HIWORD(lParam);
        
        // Check button clicks (example areas)
        if (mx >= 20 && mx <= 150 && my >= 600 && my <= 635) {
            DoSpoofHWID();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (mx >= 170 && mx <= 300 && my >= 600 && my <= 635) {
            DoRevertHWID();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (mx >= 320 && mx <= 450 && my >= 600 && my <= 635) {
            DoCleanTraces();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (mx >= 470 && mx <= 600 && my >= 600 && my <= 635) {
            RefreshCurrentHWIDs();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        return 0;
    }
    
    case WM_MOUSEMOVE: {
        int mx = LOWORD(lParam);
        int my = HIWORD(lParam);
        
        // Track hover states
        BOOL newHoverChange = (mx >= 20 && mx <= 150 && my >= 600 && my <= 635);
        BOOL newHoverRevert = (mx >= 170 && mx <= 300 && my >= 600 && my <= 635);
        BOOL newHoverClean = (mx >= 320 && mx <= 450 && my >= 600 && my <= 635);
        BOOL newHoverRefresh = (mx >= 470 && mx <= 600 && my >= 600 && my <= 635);
        
        if (newHoverChange != g_HoverChange || newHoverRevert != g_HoverRevert ||
            newHoverClean != g_HoverCleanTraces || newHoverRefresh != g_HoverRefresh) {
            g_HoverChange = newHoverChange;
            g_HoverRevert = newHoverRevert;
            g_HoverCleanTraces = newHoverClean;
            g_HoverRefresh = newHoverRefresh;
            InvalidateRect(hWnd, NULL, FALSE);
        }
        
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hWnd, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }
    
    case WM_MOUSELEAVE: {
        if (g_HoverChange || g_HoverRevert || g_HoverCleanTraces || g_HoverRefresh) {
            g_HoverChange = FALSE;
            g_HoverRevert = FALSE;
            g_HoverCleanTraces = FALSE;
            g_HoverRefresh = FALSE;
            InvalidateRect(hWnd, NULL, FALSE);
        }
        return 0;
    }
    
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC hdcStatic = (HDC)wParam;
        SetTextColor(hdcStatic, CLR_TEXT);
        SetBkColor(hdcStatic, CLR_PANEL);
        return (LRESULT)g_hBrPanel;
    }
    
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        switch (wmId) {
        case IDC_BTN_CHANGE:
            DoSpoofHWID();
            InvalidateRect(hWnd, NULL, TRUE);
            break;
        case IDC_BTN_REVERT:
            DoRevertHWID();
            InvalidateRect(hWnd, NULL, TRUE);
            break;
        case IDC_BTN_CLEAN_TRACES:
            DoCleanTraces();
            InvalidateRect(hWnd, NULL, TRUE);
            break;
        case IDC_BTN_REFRESH:
            RefreshCurrentHWIDs();
            InvalidateRect(hWnd, NULL, TRUE);
            break;
        }
        return 0;
    }
    
    case WM_DESTROY: {
        // Cleanup
        DestroyFonts();
        if (g_hBrBg) DeleteObject(g_hBrBg);
        if (g_hBrPanel) DeleteObject(g_hBrPanel);
        if (g_hBrBorder) DeleteObject(g_hBrBorder);
        
        KillTimer(hWnd, IDT_COUNTDOWN_TIMER);
        PostQuitMessage(0);
        return 0;
    }
    
    default:
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
}

// ==================== GUI UPDATE FUNCTIONS ====================

void GUI_Invalidate(void) {
    if (g_hWnd) {
        InvalidateRect(g_hWnd, NULL, TRUE);
    }
}

void GUI_SetStatus(const char* text, COLORREF color) {
    strncpy_s(g_StatusText, sizeof(g_StatusText), text, _TRUNCATE);
    g_StatusColor = color;
    GUI_Invalidate();
}

void GUI_UpdateHWIDDisplay(void) {
    GUI_Invalidate();
}

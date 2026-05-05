/*
 * HWID Spoofer - GUI Window Module
 * Main window procedure and message handling
 */

#include "gui_main.h"
#include "gui_draw.h"
#include "../manager.h"
#include "../HWID/hwid_reader.h"
#include "../Core/core_spoof.h"
#include "../Utils/utils_common.h"

// ==================== WINDOW PROCEDURE ====================

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        g_hBrBg    = CreateSolidBrush(CLR_BG);
        g_hBrPanel = CreateSolidBrush(CLR_PANEL);
        g_hBrBorder = CreateSolidBrush(CLR_BORDER);
        InitFonts();

        // Duration combo
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
        strcpy_s(g_CurrentDiskSerial, sizeof(g_CurrentDiskSerial), g_OriginalDiskSerial);
        memcpy(g_CurrentMAC, g_OriginalMAC, 6);
        g_CurrentMACValid = g_OriginalMACValid;
        strcpy_s(g_CurrBIOSSerial, sizeof(g_CurrBIOSSerial), g_OrigBIOSSerial);
        strcpy_s(g_CurrBoardSerial, sizeof(g_CurrBoardSerial), g_OrigBoardSerial);
        strcpy_s(g_CurrSystemUUID, sizeof(g_CurrSystemUUID), g_OrigSystemUUID);
        g_CurrVolumeSerial = g_OrigVolumeSerial;
        g_CurrVolumeSerialValid = g_OrigVolumeSerialValid;
        strcpy_s(g_CurrGPUID, sizeof(g_CurrGPUID), g_OrigGPUID);

        if (!CreateHiddenTempDirectory()) {
            MessageBoxA(hWnd, "Failed to create temp directory.", "Error", MB_ICONERROR);
        }

        // Countdown timer (1 second)
        SetTimer(hWnd, IDT_COUNTDOWN_TIMER, 1000, NULL);
        return 0;
    }

    case WM_TIMER: {
        if (wParam == IDT_DURATION_TIMER) {
            // Duration expired - auto revert
            KillTimer(hWnd, IDT_DURATION_TIMER);
            g_SpoofExpiry = 0;
            DoRevertHWID();
            InvalidateRect(hWnd, NULL, TRUE);
        }
        else if (wParam == IDT_COUNTDOWN_TIMER) {
            if (g_SpooferLoaded && g_SpoofExpiry > 0) {
                ULONGLONG now = GetTickCount64();
                if (now >= g_SpoofExpiry) {
                    KillTimer(hWnd, IDT_DURATION_TIMER);
                    g_SpoofExpiry = 0;
                    DoRevertHWID();
                    InvalidateRect(hWnd, NULL, TRUE);
                    return 0;
                } else {
                    ULONGLONG remaining = (g_SpoofExpiry - now) / 1000;
                    int days = (int)(remaining / 86400);
                    int hours = (int)((remaining % 86400) / 3600);
                    int mins = (int)((remaining % 3600) / 60);
                    int secs = (int)(remaining % 60);
                    if (days > 0)
                        sprintf_s(g_TimeRemaining, sizeof(g_TimeRemaining),
                                  "%dd %02dh %02dm %02ds", days, hours, mins, secs);
                    else
                        sprintf_s(g_TimeRemaining, sizeof(g_TimeRemaining),
                                  "%02dh %02dm %02ds", hours, mins, secs);
                }
                InvalidateRect(hWnd, NULL, FALSE);
            }
        }
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT clientRect;
        GetClientRect(hWnd, &clientRect);

        // Double buffer
        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP memBmp = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
        SelectObject(memDC, memBmp);

        // Background
        FillRect(memDC, &clientRect, g_hBrBg);

        // Title with Hex styling
        SetBkMode(memDC, TRANSPARENT);
        SelectObject(memDC, g_hFontTitle);
        SetTextColor(memDC, CLR_ACCENT);
        TextOutA(memDC, 25, 20, "Hex", 3);
        
        SIZE sz;
        GetTextExtentPoint32A(memDC, "Hex", 3, &sz);
        SetTextColor(memDC, CLR_TEXT);
        TextOutA(memDC, 25 + sz.cx + 8, 20, "- Cleaner", 9);

        // Version in corner
        SelectObject(memDC, g_hFontSmall);
        SetTextColor(memDC, CLR_TEXT_DIM);
        TextOutA(memDC, clientRect.right - 80, 28, "v1.5.8", 6);

        int col1X = 20;
        int col2X = 240;
        int col3X = 460;
        int sectionY = 65;
        int sectionW = 205;
        int sectionH = 125;
        int checkboxSize = 16;

        // === WiFi FUNCTIONS ===
        DrawSection(memDC, col1X, sectionY, sectionW, sectionH, "WiFi FUNCTIONS");
        {
            int y = sectionY + 35;
            int checkX = col1X + 15;
            int labelX = checkX + checkboxSize + 8;
            
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkFlushDNS, g_HoverCheckbox == IDC_CHK_FLUSH_DNS, "FlushDNS", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkTCPReset, g_HoverCheckbox == IDC_CHK_TCP_RESET, "TCP Reset", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkWiFiReset, g_HoverCheckbox == IDC_CHK_WIFI_RESET, "Full WiFi Reset", labelX);
        }

        // === FILE FUNCTIONS ===
        DrawSection(memDC, col2X, sectionY, sectionW, sectionH, "FILE FUNCTIONS");
        {
            int y = sectionY + 35;
            int checkX = col2X + 15;
            int labelX = checkX + checkboxSize + 8;
            
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkTempFiles, g_HoverCheckbox == IDC_CHK_TEMP_FILES, "Temporary Files", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkWinTemp, g_HoverCheckbox == IDC_CHK_WIN_TEMP, "Windows Temp Folder", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkWinLogs, g_HoverCheckbox == IDC_CHK_WIN_LOGS, "Windows Logs", labelX);
        }

        // === BROWSER FUNCTIONS ===
        DrawSection(memDC, col3X, sectionY, sectionW, sectionH, "BROWSER FUNCTIONS (testing)");
        {
            int y = sectionY + 35;
            int checkX = col3X + 15;
            int labelX = checkX + checkboxSize + 8;
            
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkChromeCookies, g_HoverCheckbox == IDC_CHK_CHROME_COOK, "Chrome Cookies", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkFirefoxCookies, g_HoverCheckbox == IDC_CHK_FIREFOX_COOK, "Firefox Cookies", labelX);
        }

        // === ANTI-CHEAT TERMINATOR ===
        int section2Y = sectionY + sectionH + 15;
        DrawSection(memDC, col1X, section2Y, sectionW * 2 + 20, 150, "ANTI-CHEAT TERMINATOR (testing)");
        {
            int y = section2Y + 35;
            int checkX = col1X + 15;
            int labelX = checkX + checkboxSize + 8;
            
            // First column
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkFortnite, g_HoverCheckbox == IDC_CHK_FORTNITE, "Fortnite", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkFiveM, g_HoverCheckbox == IDC_CHK_FIVEM, "FiveM", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkValorant, g_HoverCheckbox == IDC_CHK_VALORANT, "Valorant", labelX);
            
            // Anti-Cheat Tracer checkbox on right side
            int check2X = col1X + sectionW + 30;
            int label2X = check2X + checkboxSize + 8;
            DrawCheckbox(memDC, check2X, section2Y + 35, checkboxSize, g_ChkAntiCheatTrace, 
                        g_HoverCheckbox == IDC_CHK_ANTICHEAT_TRACE, "Anti-Cheat Tracer", label2X);
        }

        // === UNLINK FUNCTIONS ===
        DrawSection(memDC, col3X, section2Y, sectionW, 150, "UNLINK FUNCTIONS (testing)");
        {
            int y = section2Y + 35;
            int checkX = col3X + 15;
            int labelX = checkX + checkboxSize + 8;
            
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkUnlinkXbox, g_HoverCheckbox == IDC_CHK_UNLINK_XBOX, "Unlink Xbox", labelX);
            y += 22;
            DrawCheckbox(memDC, checkX, y, checkboxSize, g_ChkUnlinkDiscord, g_HoverCheckbox == IDC_CHK_UNLINK_DISCORD, "Unlink Discord", labelX);
        }

        // === BOTTOM BUTTONS ===
        int btnY = clientRect.bottom - 70;
        int btnW = 200;
        int btnH = 45;
        int btnGap = 40;
        int startX = (clientRect.right - (btnW * 2 + btnGap)) / 2;
        
        // Start Cleaning button (Pink)
        RECT rcStartClean = {startX, btnY, startX + btnW, btnY + btnH};
        DrawHexButton(memDC, &rcStartClean, "Start Cleaning", CLR_BTN_MAIN, g_HoverStartClean);
        
        // Spoof All button (Purple)
        RECT rcSpoofAll = {startX + btnW + btnGap, btnY, startX + btnW * 2 + btnGap, btnY + btnH};
        DrawHexButton(memDC, &rcSpoofAll, "Spoof All", CLR_BTN_SPOOF, g_HoverSpoofAll);

        // Blit
        BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, memDC, 0, 0, SRCCOPY);
        DeleteObject(memBmp);
        DeleteDC(memDC);

        EndPaint(hWnd, &ps);
        return 0;
    }

    case WM_LBUTTONDOWN: {
        int mx = LOWORD(lParam);
        int my = HIWORD(lParam);
        int checkboxSize = 16;
        
        // Helper to check if click is in checkbox area
        #define CHECKBOX_HIT(x, y, cx, cy) (mx >= cx && mx <= cx + checkboxSize && my >= cy && my <= cy + checkboxSize)
        
        int col1X = 20, col2X = 240, col3X = 460;
        int sectionY = 65, sectionH = 125;
        int checkX1 = col1X + 15, checkX2 = col2X + 15, checkX3 = col3X + 15;
        
        // WiFi Functions checkboxes
        int yWifi = sectionY + 35;
        if (CHECKBOX_HIT(mx, my, checkX1, yWifi)) { g_ChkFlushDNS = !g_ChkFlushDNS; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, checkX1, yWifi + 22)) { g_ChkTCPReset = !g_ChkTCPReset; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, checkX1, yWifi + 44)) { g_ChkWiFiReset = !g_ChkWiFiReset; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        
        // File Functions checkboxes
        int yFile = sectionY + 35;
        if (CHECKBOX_HIT(mx, my, checkX2, yFile)) { g_ChkTempFiles = !g_ChkTempFiles; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, checkX2, yFile + 22)) { g_ChkWinTemp = !g_ChkWinTemp; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, checkX2, yFile + 44)) { g_ChkWinLogs = !g_ChkWinLogs; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        
        // Browser Functions checkboxes
        int yBrowser = sectionY + 35;
        if (CHECKBOX_HIT(mx, my, checkX3, yBrowser)) { g_ChkChromeCookies = !g_ChkChromeCookies; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, checkX3, yBrowser + 22)) { g_ChkFirefoxCookies = !g_ChkFirefoxCookies; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        
        // Anti-Cheat checkboxes
        int section2Y = sectionY + sectionH + 15;
        int yAntiCheat = section2Y + 35;
        int check2X = col1X + 15;
        int check3X = col1X + 205 + 30;
        
        if (CHECKBOX_HIT(mx, my, check2X, yAntiCheat)) { g_ChkFortnite = !g_ChkFortnite; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, check2X, yAntiCheat + 22)) { g_ChkFiveM = !g_ChkFiveM; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, check2X, yAntiCheat + 44)) { g_ChkValorant = !g_ChkValorant; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, check3X, yAntiCheat)) { g_ChkAntiCheatTrace = !g_ChkAntiCheatTrace; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        
        // Unlink Functions checkboxes
        int yUnlink = section2Y + 35;
        int checkX4 = col3X + 15;
        if (CHECKBOX_HIT(mx, my, checkX4, yUnlink)) { g_ChkUnlinkXbox = !g_ChkUnlinkXbox; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        if (CHECKBOX_HIT(mx, my, checkX4, yUnlink + 22)) { g_ChkUnlinkDiscord = !g_ChkUnlinkDiscord; InvalidateRect(hWnd, NULL, FALSE); return 0; }
        
        #undef CHECKBOX_HIT
        
        // Bottom buttons
        RECT clientRect;
        GetClientRect(hWnd, &clientRect);
        int btnY = clientRect.bottom - 70;
        int btnW = 200, btnH = 45, btnGap = 40;
        int startX = (clientRect.right - (btnW * 2 + btnGap)) / 2;
        
        // Start Cleaning button
        if (mx >= startX && mx <= startX + btnW && my >= btnY && my <= btnY + btnH) {
            DoStartCleaning();
            InvalidateRect(hWnd, NULL, TRUE);
            return 0;
        }
        
        // Spoof All button
        if (mx >= startX + btnW + btnGap && mx <= startX + btnW * 2 + btnGap && my >= btnY && my <= btnY + btnH) {
            DoSpoofAll();
            InvalidateRect(hWnd, NULL, TRUE);
            return 0;
        }
        
        return 0;
    }

    case WM_MOUSEMOVE: {
        int mx = LOWORD(lParam);
        int my = HIWORD(lParam);
        int checkboxSize = 16;
        
        int col1X = 20, col2X = 240, col3X = 460;
        int sectionY = 65, sectionH = 125;
        int section2Y = sectionY + sectionH + 15;
        
        RECT clientRect;
        GetClientRect(hWnd, &clientRect);
        int btnY = clientRect.bottom - 70;
        int btnW = 200, btnH = 45, btnGap = 40;
        int startX = (clientRect.right - (btnW * 2 + btnGap)) / 2;
        
        // Check button hovers
        BOOL newHoverStart = (mx >= startX && mx <= startX + btnW && my >= btnY && my <= btnY + btnH);
        BOOL newHoverSpoof = (mx >= startX + btnW + btnGap && mx <= startX + btnW * 2 + btnGap && my >= btnY && my <= btnY + btnH);
        
        if (newHoverStart != g_HoverStartClean || newHoverSpoof != g_HoverSpoofAll) {
            g_HoverStartClean = newHoverStart;
            g_HoverSpoofAll = newHoverSpoof;
            InvalidateRect(hWnd, NULL, FALSE);
        }
        
        // Check checkbox hovers
        int newHoverChk = -1;
        
        // WiFi checkboxes
        int yWifi = sectionY + 35;
        if (mx >= col1X + 15 && mx <= col1X + 15 + checkboxSize && my >= yWifi && my <= yWifi + checkboxSize) newHoverChk = IDC_CHK_FLUSH_DNS;
        else if (mx >= col1X + 15 && mx <= col1X + 15 + checkboxSize && my >= yWifi + 22 && my <= yWifi + 22 + checkboxSize) newHoverChk = IDC_CHK_TCP_RESET;
        else if (mx >= col1X + 15 && mx <= col1X + 15 + checkboxSize && my >= yWifi + 44 && my <= yWifi + 44 + checkboxSize) newHoverChk = IDC_CHK_WIFI_RESET;
        // File checkboxes
        else if (mx >= col2X + 15 && mx <= col2X + 15 + checkboxSize && my >= yWifi && my <= yWifi + checkboxSize) newHoverChk = IDC_CHK_TEMP_FILES;
        else if (mx >= col2X + 15 && mx <= col2X + 15 + checkboxSize && my >= yWifi + 22 && my <= yWifi + 22 + checkboxSize) newHoverChk = IDC_CHK_WIN_TEMP;
        else if (mx >= col2X + 15 && mx <= col2X + 15 + checkboxSize && my >= yWifi + 44 && my <= yWifi + 44 + checkboxSize) newHoverChk = IDC_CHK_WIN_LOGS;
        // Browser checkboxes
        else if (mx >= col3X + 15 && mx <= col3X + 15 + checkboxSize && my >= yWifi && my <= yWifi + checkboxSize) newHoverChk = IDC_CHK_CHROME_COOK;
        else if (mx >= col3X + 15 && mx <= col3X + 15 + checkboxSize && my >= yWifi + 22 && my <= yWifi + 22 + checkboxSize) newHoverChk = IDC_CHK_FIREFOX_COOK;
        // Anti-Cheat
        else if (mx >= col1X + 15 && mx <= col1X + 15 + checkboxSize && my >= section2Y + 35 && my <= section2Y + 35 + checkboxSize) newHoverChk = IDC_CHK_FORTNITE;
        else if (mx >= col1X + 15 && mx <= col1X + 15 + checkboxSize && my >= section2Y + 35 + 22 && my <= section2Y + 35 + 22 + checkboxSize) newHoverChk = IDC_CHK_FIVEM;
        else if (mx >= col1X + 15 && mx <= col1X + 15 + checkboxSize && my >= section2Y + 35 + 44 && my <= section2Y + 35 + 44 + checkboxSize) newHoverChk = IDC_CHK_VALORANT;
        else if (mx >= col1X + 205 + 30 && mx <= col1X + 205 + 30 + checkboxSize && my >= section2Y + 35 && my <= section2Y + 35 + checkboxSize) newHoverChk = IDC_CHK_ANTICHEAT_TRACE;
        // Unlink
        else if (mx >= col3X + 15 && mx <= col3X + 15 + checkboxSize && my >= section2Y + 35 && my <= section2Y + 35 + checkboxSize) newHoverChk = IDC_CHK_UNLINK_XBOX;
        else if (mx >= col3X + 15 && mx <= col3X + 15 + checkboxSize && my >= section2Y + 35 + 22 && my <= section2Y + 35 + 22 + checkboxSize) newHoverChk = IDC_CHK_UNLINK_DISCORD;
        
        if (newHoverChk != g_HoverCheckbox) {
            g_HoverCheckbox = newHoverChk;
            InvalidateRect(hWnd, NULL, FALSE);
        }

        // Track mouse leave
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hWnd, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }

    case WM_MOUSELEAVE: {
        if (g_HoverStartClean || g_HoverSpoofAll || g_HoverCheckbox != -1) {
            g_HoverStartClean = FALSE;
            g_HoverSpoofAll = FALSE;
            g_HoverCheckbox = -1;
            InvalidateRect(hWnd, NULL, FALSE);
        }
        return 0;
    }

    case WM_CTLCOLORLISTBOX:
    case WM_CTLCOLOREDIT: {
        HDC hdcCtl = (HDC)wParam;
        SetTextColor(hdcCtl, CLR_TEXT);
        SetBkColor(hdcCtl, CLR_PANEL);
        return (LRESULT)g_hBrPanel;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_COMBO_DURATION && HIWORD(wParam) == CBN_SELCHANGE) {
            g_SelectedDuration = (int)SendMessageA(g_hComboDuration, CB_GETCURSEL, 0, 0);
        }
        return 0;
    }

    case WM_ERASEBKGND:
        return 1;

    case WM_DESTROY: {
        KillTimer(hWnd, IDT_DURATION_TIMER);
        KillTimer(hWnd, IDT_COUNTDOWN_TIMER);
        if (g_SpooferLoaded) {
            SignalDriverRevert();
            UnloadSpooferDriver();
        }
        CleanupTempFiles();
        DestroyFonts();
        DeleteObject(g_hBrBg);
        DeleteObject(g_hBrPanel);
        DeleteObject(g_hBrBorder);
        PostQuitMessage(0);
        return 0;
    }

    default:
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
}

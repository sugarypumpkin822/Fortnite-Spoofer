/*
 * GUI Drawing Functions Implementation
 * HWID Spoofer - Custom Drawing Routines
 */

#include "gui_draw.h"
#include <string.h>

// Font handles - defined here, declared extern in header
HFONT g_hFontTitle  = NULL;
HFONT g_hFontNormal = NULL;
HFONT g_hFontSmall  = NULL;
HFONT g_hFontBold   = NULL;
HFONT g_hFontMono   = NULL;

// Brush handles - defined here, declared extern in header
HBRUSH g_hBrBg    = NULL;
HBRUSH g_hBrPanel = NULL;
HBRUSH g_hBrBorder = NULL;

// ==================== FONT FUNCTIONS ====================

void InitFonts(void) {
    g_hFontTitle  = CreateFontA(28, 0, 0, 0, FW_BOLD, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontNormal = CreateFontA(13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontSmall  = CreateFontA(11, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontBold   = CreateFontA(13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_hFontMono   = CreateFontA(12, 0, 0, 0, FW_NORMAL, 0, 0, 0,
        DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Consolas");
}

void DestroyFonts(void) {
    if (g_hFontTitle)  DeleteObject(g_hFontTitle);
    if (g_hFontNormal) DeleteObject(g_hFontNormal);
    if (g_hFontSmall)  DeleteObject(g_hFontSmall);
    if (g_hFontBold)   DeleteObject(g_hFontBold);
    if (g_hFontMono)   DeleteObject(g_hFontMono);
    
    g_hFontTitle = g_hFontNormal = g_hFontSmall = g_hFontBold = g_hFontMono = NULL;
}

// ==================== DRAWING FUNCTIONS ====================

void DrawPanel(HDC hdc, RECT* rc, const char* title) {
    HBRUSH br = CreateSolidBrush(CLR_PANEL);
    HPEN pen = CreatePen(PS_SOLID, 1, CLR_BORDER);
    SelectObject(hdc, br);
    SelectObject(hdc, pen);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, 10, 10);
    DeleteObject(br);
    DeleteObject(pen);

    if (title) {
        SelectObject(hdc, g_hFontBold);
        SetTextColor(hdc, CLR_ACCENT);
        SetBkMode(hdc, TRANSPARENT);
        TextOutA(hdc, rc->left + 14, rc->top + 10, title, (int)strlen(title));
    }
}

void DrawTextLine(HDC hdc, int x, int y, const char* label, const char* value, COLORREF valColor) {
    SetBkMode(hdc, TRANSPARENT);

    SelectObject(hdc, g_hFontNormal);
    SetTextColor(hdc, CLR_TEXT_DIM);
    TextOutA(hdc, x, y, label, (int)strlen(label));

    SelectObject(hdc, g_hFontMono);
    SetTextColor(hdc, valColor);
    TextOutA(hdc, x + 120, y, value, (int)strlen(value));
}

void DrawButton(HDC hdc, RECT* rc, const char* text, COLORREF bgColor, BOOL hover) {
    COLORREF col = hover ? (bgColor == CLR_BTN_MAIN ? CLR_BTN_MAIN_H : 
                             (bgColor == CLR_BTN_SPOOF ? CLR_BTN_SPOOF_H : bgColor)) : bgColor;
    HBRUSH br = CreateSolidBrush(col);
    HPEN pen = CreatePen(PS_SOLID, 1, col);
    SelectObject(hdc, br);
    SelectObject(hdc, pen);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, 8, 8);
    DeleteObject(br);
    DeleteObject(pen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_WHITE);
    SelectObject(hdc, g_hFontBold);
    DrawTextA(hdc, text, -1, rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void DrawSection(HDC hdc, int x, int y, int w, int h, const char* title) {
    // Section background
    HBRUSH br = CreateSolidBrush(CLR_SECTION_BG);
    HPEN pen = CreatePen(PS_SOLID, 1, CLR_BORDER);
    SelectObject(hdc, br);
    SelectObject(hdc, pen);
    RoundRect(hdc, x, y, x + w, y + h, 6, 6);
    DeleteObject(br);
    DeleteObject(pen);
    
    // Title
    SetBkMode(hdc, TRANSPARENT);
    SelectObject(hdc, g_hFontBold);
    SetTextColor(hdc, CLR_ACCENT);
    TextOutA(hdc, x + 12, y + 8, title, (int)strlen(title));
}

void DrawCheckbox(HDC hdc, int x, int y, int size, BOOL checked, BOOL hovered, const char* label, int labelX) {
    // Checkbox background
    COLORREF boxColor = hovered ? CLR_ACCENT : CLR_BORDER;
    HBRUSH br = CreateSolidBrush(checked ? CLR_CHECKBOX : CLR_PANEL);
    HPEN pen = CreatePen(PS_SOLID, 2, boxColor);
    SelectObject(hdc, br);
    SelectObject(hdc, pen);
    RoundRect(hdc, x, y, x + size, y + size, 4, 4);
    DeleteObject(br);
    DeleteObject(pen);
    
    // Checkmark
    if (checked) {
        HPEN checkPen = CreatePen(PS_SOLID, 2, CLR_WHITE);
        SelectObject(hdc, checkPen);
        
        // Draw checkmark
        MoveToEx(hdc, x + 4, y + size/2, NULL);
        LineTo(hdc, x + size/2 - 2, y + size - 5);
        LineTo(hdc, x + size - 4, y + 4);
        
        DeleteObject(checkPen);
    }
    
    // Label
    SetBkMode(hdc, TRANSPARENT);
    SelectObject(hdc, g_hFontNormal);
    SetTextColor(hdc, checked ? CLR_TEXT : CLR_TEXT_DIM);
    TextOutA(hdc, labelX, y + 2, label, (int)strlen(label));
}

void DrawHexButton(HDC hdc, RECT* rc, const char* text, COLORREF bgColor, BOOL hover) {
    COLORREF col = hover ? 
        (bgColor == CLR_BTN_MAIN ? RGB(244, 114, 182) : RGB(167, 139, 250)) : bgColor;
    
    // Button shadow
    HBRUSH shadowBr = CreateSolidBrush(RGB(0, 0, 0));
    SelectObject(hdc, shadowBr);
    SelectObject(hdc, GetStockObject(NULL_PEN));
    RoundRect(hdc, rc->left + 2, rc->top + 2, rc->right + 2, rc->bottom + 2, 10, 10);
    DeleteObject(shadowBr);
    
    // Button background
    HBRUSH br = CreateSolidBrush(col);
    HPEN pen = CreatePen(PS_SOLID, 1, col);
    SelectObject(hdc, br);
    SelectObject(hdc, pen);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, 10, 10);
    DeleteObject(br);
    DeleteObject(pen);
    
    // Button text
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, CLR_WHITE);
    SelectObject(hdc, g_hFontBold);
    DrawTextA(hdc, text, -1, rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

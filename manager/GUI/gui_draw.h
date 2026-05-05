/*
 * GUI Drawing Functions Header
 * HWID Spoofer - Custom Drawing Routines
 */

#ifndef GUI_DRAW_H
#define GUI_DRAW_H

#include <windows.h>
#include "gui_colors.h"

#ifdef __cplusplus
extern "C" {
#endif

// Font handles (extern - defined in gui_main.c)
extern HFONT g_hFontTitle;
extern HFONT g_hFontNormal;
extern HFONT g_hFontSmall;
extern HFONT g_hFontBold;
extern HFONT g_hFontMono;

// Brush handles (extern - defined in gui_main.c)
extern HBRUSH g_hBrBg;
extern HBRUSH g_hBrPanel;
extern HBRUSH g_hBrBorder;

// ==================== FONT FUNCTIONS ====================

// Initialize all fonts
void InitFonts(void);

// Destroy all fonts
void DestroyFonts(void);

// ==================== DRAWING FUNCTIONS ====================

// Draw a panel with rounded corners
void DrawPanel(HDC hdc, RECT* rc, const char* title);

// Draw a text line with label and value
void DrawTextLine(HDC hdc, int x, int y, const char* label, const char* value, COLORREF valColor);

// Draw a button with hover effect
void DrawButton(HDC hdc, RECT* rc, const char* text, COLORREF bgColor, BOOL hover);

// Draw a hex-themed button with shadow
void DrawHexButton(HDC hdc, RECT* rc, const char* text, COLORREF bgColor, BOOL hover);

// Draw a section box with title
void DrawSection(HDC hdc, int x, int y, int w, int h, const char* title);

// Draw a checkbox with label
void DrawCheckbox(HDC hdc, int x, int y, int size, BOOL checked, BOOL hovered, const char* label, int labelX);

#ifdef __cplusplus
}
#endif

#endif // GUI_DRAW_H

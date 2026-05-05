/*
 * HWID Spoofer - Main Entry Point
 * 
 * This is the application entry point (WinMain).
 * All other functionality is split into modular components:
 * - Core/      - Spoofing operations and business logic
 * - Driver/    - KDMapper integration and kernel operations  
 * - GUI/       - Window management and rendering
 * - HWID/      - Hardware ID reading
 * - Utils/     - Common utilities and helpers
 * - trace_cleaners/ - System trace cleaning modules
 */

#include "manager.h"

// Enable visual styles (Windows XP and later)
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include "GUI/gui_main.h"
#include "GUI/gui_draw.h"
#include "Core/core_spoof.h"
#include "HWID/hwid_reader.h"
#include "Utils/utils_common.h"

// Entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hPrev; (void)lpCmd;
    g_hInst = hInstance;

    if (!IsAdmin()) {
        MessageBoxA(NULL,
            "Administrator privileges required!\n\nRight-click and select 'Run as Administrator'.",
            "HWID Spoofer", MB_ICONERROR | MB_OK);
        return 1;
    }

    srand((unsigned int)time(NULL) ^ GetTickCount());

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXA wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInstance;
    wc.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground  = NULL;
    wc.lpszClassName  = "HWIDSpooferWnd";
    wc.hIcon          = LoadIcon(NULL, IDI_SHIELD);
    wc.hIconSm        = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassExA(&wc);

    int wndW = 700, wndH = 850;
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);

    g_hWnd = CreateWindowExA(
        0, "HWIDSpooferWnd", "Hex Spoofer - Cleaner",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (scrW - wndW) / 2, (scrH - wndH) / 2, wndW, wndH,
        NULL, NULL, hInstance, NULL);

    ShowWindow(g_hWnd, nShow);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

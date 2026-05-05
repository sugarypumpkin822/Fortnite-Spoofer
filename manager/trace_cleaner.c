/*
 * HWID Spoofer - Trace Cleaner Module
 * 
 * Comprehensive system trace cleaning to remove forensic artifacts.
 * This is the main module that includes all trace cleaner components.
 * 
 * The trace cleaners are organized in the trace_cleaners/ folder:
 * - tc_common.c/h       - Common utility functions
 * - tc_eventlogs.c/h    - Windows Event Log cleaning
 * - tc_registry.c/h     - Registry trace cleaning
 * - tc_filesystem.c/h   - Prefetch, Recent Items, Jump Lists, Temp Files, Thumbnails, Shellbags
 * - tc_usn.c/h          - USN Journal cleaning
 * - tc_browser.c/h      - Browser trace cleaning
 * - tc_wer.c/h          - Windows Error Reporting cleaning
 * - tc_search.c/h       - Search Index and Superfetch cleaning
 * - tc_network.c/h      - DNS and ARP cache cleaning
 * - tc_clipboard.c/h    - Clipboard cleaning
 * - tc_api.c/h          - Main API functions
 */

#include "trace_cleaner.h"

// Include all trace cleaner implementations
#include "trace_cleaners/tc_common.c"
#include "trace_cleaners/tc_eventlogs.c"
#include "trace_cleaners/tc_registry.c"
#include "trace_cleaners/tc_filesystem.c"
#include "trace_cleaners/tc_usn.c"
#include "trace_cleaners/tc_browser.c"
#include "trace_cleaners/tc_wer.c"
#include "trace_cleaners/tc_search.c"
#include "trace_cleaners/tc_network.c"
#include "trace_cleaners/tc_clipboard.c"
#include "trace_cleaners/tc_api.c"

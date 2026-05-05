/*
 * HWID Spoofer - Core Spoofing Module Header
 * Main spoofing operations and trace cleaning
 */

#ifndef CORE_SPOOF_H
#define CORE_SPOOF_H

#include "../manager.h"

#ifdef __cplusplus
extern "C" {
#endif

// Main spoofing operations
void DoSpoofHWID(void);
void DoRevertHWID(void);
void DoCleanTraces(void);
void DoStartCleaning(void);
void DoSpoofAll(void);

// Status updates
void UpdateStatus(void);

// Signal driver to revert
void SignalDriverRevert(void);

#ifdef __cplusplus
}
#endif

#endif // CORE_SPOOF_H

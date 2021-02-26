// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// UT.h
// Header of UT.c

#ifndef	UT_H
#define	UT_H

// Constant
#define	SPEED_METER_REFRESH_INTERVAL			500

#ifdef	UT_C
// For internal declaration

// Function prototype
UINT UtSpeedMeterDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void UtSpeedMeterDlgInit(HWND hWnd);
void UtSpeedMeterDlgRefreshList(HWND hWnd);
void UtSpeedMeterDlgRefreshStatus(HWND hWnd);
void UtSpeedMeterDlgUpdate(HWND hWnd);
void UtSpeedMeterDlgRefreshStatus(HWND hWnd);

#endif	// UT_C

// Function prototype
void UtSpeedMeterEx(void *hWnd);

#endif	// UT_H


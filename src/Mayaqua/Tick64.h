// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Tick64.h
// Header of Tick64.c

#ifndef	TICK64_H
#define	TICK64_H

#include "MayaType.h"

// Maximum number of correction list entries
#define	MAX_ADJUST_TIME				1024

// Correction list entry
struct ADJUST_TIME
{
	UINT64 Tick;
	UINT64 Time;
};

// TICK64 structure
struct TICK64
{
	THREAD *Thread;
	UINT64 Tick;
	UINT64 TickStart;
	UINT64 Time64;
	UINT64 Tick64WithTime64;
	UINT LastTick;
	UINT RoundCount;
	LOCK *TickLock;
	volatile bool Halt;
	LIST *AdjustTime;
};

// Constant
#define	TICK64_SPAN			10		// Measurement interval (Usually less than 10ms)
#define	TICK64_SPAN_WIN32	1000	// Interval of measurement on Win32
#define	TICK64_ADJUST_SPAN	5000	// Correct the clock if it shifts more than this value

// Function prototype
void InitTick64();
void FreeTick64();
void Tick64Thread(THREAD *thread, void *param);
UINT64 Tick64();
UINT64 Diff64(UINT64 a, UINT64 b);
UINT64 Tick64ToTime64(UINT64 tick);
UINT64 TickToTime(UINT64 tick);
UINT64 TickHighres64();

#endif	// TICK64_H




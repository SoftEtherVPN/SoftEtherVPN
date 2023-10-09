// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Tick64.c
// 64-bit real-time clock program

#include "Tick64.h"

#include "Kernel.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Str.h"
#include "Unix.h"
#include "Win32.h"

static TICK64 *tk64 = NULL;
static EVENT *halt_tick_event = NULL;

// Get the high-resolution time
UINT64 TickHighres64()
{

#ifdef	OS_WIN32

	return (UINT64)(MsGetHiResTimeSpan(MsGetHiResCounter()) * 1000.0f);

#else	// OS_WIN32

	return Tick64();

#endif	// OS_WIN32

}

UINT64 TickHighresNano64(bool raw)
{
	UINT64 ret = 0;

#ifdef	OS_WIN32

	ret = (UINT64)(MsGetHiResTimeSpan(MsGetHiResCounter()) * 1000000000.0f);

#else	// OS_WIN32

	ret = UnixGetHighresTickNano64(raw);

#endif	// OS_WIN32

	return ret;
}

// Convert the Tick value to time
UINT64 Tick64ToTime64(UINT64 tick)
{
	UINT64 ret = 0;
	if (tick == 0)
	{
		return 0;
	}
	LockList(tk64->AdjustTime);
	{
		INT i;
		for (i = ((INT)LIST_NUM(tk64->AdjustTime) - 1); i >= 0; i--)
		{
			ADJUST_TIME *t = LIST_DATA(tk64->AdjustTime, i);
			if (t->Tick <= tick)
			{
				ret = t->Time + (tick - t->Tick);
				break;
			}
		}
	}
	UnlockList(tk64->AdjustTime);
	if (ret == 0)
	{
		ret++;
	}
	return ret;
}

// Convert the Tick value to time
UINT64 TickToTime(UINT64 tick)
{
	return Tick64ToTime64(tick);
}

// Get the Tick value
UINT64 Tick64()
{
#ifdef	OS_WIN32
	return Win32FastTick64();
#else	// OS_WIN32
	UINT64 tick64;
	if (tk64 == NULL)
	{
		return 0;
	}
	Lock(tk64->TickLock);
	{
		tick64 = tk64->Tick;
	}
	Unlock(tk64->TickLock);
	return tick64;
#endif	// OS_WIN32
}

// Real-time clock measuring thread
void Tick64Thread(THREAD *thread, void *param)
{
	UINT n = 0;
	bool first = false;
	bool create_first_entry = true;
	UINT tick_span;
	// Validate arguments
	if (thread == NULL)
	{
		return;
	}

#ifdef	OS_WIN32

	// Raise the priority of the Win32 thread
	MsSetThreadPriorityRealtime();

	tick_span = TICK64_SPAN_WIN32;

#else	// OS_WIN32

	// Raise the priority of a POSIX threads
	UnixSetThreadPriorityRealtime();

	tick_span = TICK64_SPAN;

#endif	// OS_WIN32

	while (true)
	{
		UINT tick;
		UINT64 tick64;

#ifndef	OS_WIN32
		tick = TickRealtime();		// Get the current system clock

		if (tk64->LastTick > tick)
		{
			if ((tk64->LastTick - tick) >= (UINT64)0x0fffffff)
			{
				// The Tick has gone lap around
				tk64->RoundCount++;
			}
			else
			{
				// tick skewed (System administrator might change hardware clock)
				// Normally, the clock skew appears as sub-seconds error
				tick = tk64->LastTick;
			}
		}
		tk64->LastTick = tick;

		tick64 = (UINT64)tk64->RoundCount * (UINT64)4294967296LL + (UINT64)tick;

		Lock(tk64->TickLock);
		{
			if (tk64->TickStart == 0)
			{
				tk64->TickStart = tick64;
			}
			tick64 = tk64->Tick = tick64 - tk64->TickStart + (UINT64)1;
		}
		Unlock(tk64->TickLock);
#else	// OS_WIN32
		tick64 = Win32FastTick64();
		tick = (UINT)tick64;
#endif	// OS_WIN32

		if (create_first_entry)
		{
			ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));
			t->Tick = tick64;
			t->Time = SystemTime64();
			tk64->Tick64WithTime64 = tick64;
			tk64->Time64 = t->Time;
			Add(tk64->AdjustTime, t);

			// Notify the completion of the initialization 
			NoticeThreadInit(thread);
			create_first_entry = false;
		}

		// Time correction
		n += tick_span;
		if (n >= 1000 || first == false)
		{
			UINT64 now = SystemTime64();

			if (now < tk64->Time64 ||
				Diff64((now - tk64->Time64) + tk64->Tick64WithTime64, tick64) >= tick_span)
			{
				ADJUST_TIME *t = ZeroMalloc(sizeof(ADJUST_TIME));
				LockList(tk64->AdjustTime);
				{
					t->Tick = tick64;
					t->Time = now;
					Add(tk64->AdjustTime, t);
					Debug("Adjust Time: Tick = %I64u, Time = %I64u\n",
						t->Tick, t->Time);

					// To prevent consuming memory infinite on a system that clock is skewd
					if (LIST_NUM(tk64->AdjustTime) > MAX_ADJUST_TIME)
					{
						// Remove the second
						ADJUST_TIME *t2 = LIST_DATA(tk64->AdjustTime, 1);

						Delete(tk64->AdjustTime, t2);

						Debug("NUM_ADJUST TIME: %u\n", LIST_NUM(tk64->AdjustTime));

						Free(t2);
					}
				}
				UnlockList(tk64->AdjustTime);
				tk64->Time64 = now;
				tk64->Tick64WithTime64 = tick64;
			}
			first = true;
			n = 0;
		}

		if (tk64->Halt)
		{
			break;
		}

#ifdef	OS_WIN32
		Wait(halt_tick_event, tick_span);
#else	// OS_WIN32
		SleepThread(tick_span);
#endif	// OS_WIN32
	}
}

// Get the absolute value of the difference between the two 64 bit integers
UINT64 Diff64(UINT64 a, UINT64 b)
{
	if (a > b)
	{
		return a - b;
	}
	else
	{
		return b - a;
	}
}

// Initialization of the Tick64
void InitTick64()
{
	if (tk64 != NULL)
	{
		// Already initialized
		return;
	}

	halt_tick_event = NewEvent();

	// Initialize the structure
	tk64 = ZeroMalloc(sizeof(TICK64));
	tk64->TickLock = NewLock();
	tk64->AdjustTime = NewList(NULL);

	// Creating a thread
	tk64->Thread = NewThread(Tick64Thread, NULL);
	WaitThreadInit(tk64->Thread);
}

// Release of the Tick64
void FreeTick64()
{
	UINT i;
	if (tk64 == NULL)
	{
		// Uninitialized
		return;
	}

	// Termination process
	tk64->Halt = true;
	Set(halt_tick_event);
	WaitThread(tk64->Thread, INFINITE);
	ReleaseThread(tk64->Thread);

	// Releasing process
	for (i = 0;i < LIST_NUM(tk64->AdjustTime);i++)
	{
		ADJUST_TIME *t = LIST_DATA(tk64->AdjustTime, i);
		Free(t);
	}
	ReleaseList(tk64->AdjustTime);
	DeleteLock(tk64->TickLock);
	Free(tk64);
	tk64 = NULL;

	ReleaseEvent(halt_tick_event);
	halt_tick_event = NULL;
}


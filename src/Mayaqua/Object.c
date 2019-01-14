// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Object.c
// Object management code

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// Thread to try to lock
void CheckDeadLockThread(THREAD *t, void *param)
{
	DEADCHECK *c = (DEADCHECK *)param;

	if (t == NULL || c == NULL)
	{
		return;
	}

	NoticeThreadInit(t);

	Lock(c->Lock);
	Unlock(c->Lock);
	c->Unlocked = true;
}

// Deadlock Detection
void CheckDeadLock(LOCK *lock, UINT timeout, char *name)
{
	DEADCHECK c;
	THREAD *t;
	char msg[MAX_PATH];

	if (lock == NULL)
	{
		return;
	}
	if (name == NULL)
	{
		name = "Unknown";
	}

	Format(msg, sizeof(msg), "error: CheckDeadLock() Failed: %s\n", name);

	Zero(&c, sizeof(c));
	c.Lock = lock;
	c.Timeout = timeout;
	c.Unlocked = false;

	t = NewThread(CheckDeadLockThread, &c);
	WaitThreadInit(t);
	if (WaitThread(t, timeout) == false)
	{
		if (c.Unlocked == false)
		{
			// Deadlock occured
			AbortExitEx(msg);
		}
		else
		{
			WaitThread(t, INFINITE);
		}
	}

	ReleaseThread(t);
}

// Create a lock object
LOCK *NewLockMain()
{
	LOCK *lock;
	UINT retry = 0;

	while (true)
	{
		if ((retry++) > OBJECT_ALLOC__MAX_RETRY)
		{
			AbortExitEx("error: OSNewLock() failed.\n\n");
		}
		lock = OSNewLock();
		if (lock != NULL)
		{
			break;
		}
		SleepThread(OBJECT_ALLOC_FAIL_SLEEP_TIME);
	}

	return lock;
}
LOCK *NewLock()
{
	LOCK *lock = NewLockMain();

	// KS
	KS_INC(KS_NEWLOCK_COUNT);
	KS_INC(KS_CURRENT_LOCK_COUNT);

	return lock;
}

// Delete the lock object
void DeleteLock(LOCK *lock)
{
	// Validate arguments
	if (lock == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_DELETELOCK_COUNT);
	KS_DEC(KS_CURRENT_LOCK_COUNT);

	OSDeleteLock(lock);
}

// Lock
bool LockInner(LOCK *lock)
{
	// Validate arguments
	if (lock == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_LOCK_COUNT);
	KS_INC(KS_CURRENT_LOCKED_COUNT);

	return OSLock(lock);
}

// Unlock
void UnlockInner(LOCK *lock)
{
	// Validate arguments
	if (lock == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_UNLOCK_COUNT);
	KS_DEC(KS_CURRENT_LOCKED_COUNT);

	OSUnlock(lock);
}

// Creating a counter
COUNTER *NewCounter()
{
	COUNTER *c;

	// Memory allocation
	c = Malloc(sizeof(COUNTER));

	// Initialization
	c->Ready = true;
	c->c = 0;

	// Lock created
	c->lock = NewLock();

	// KS
	KS_INC(KS_NEW_COUNTER_COUNT);

	return c;
}

// Delete the counter
void DeleteCounter(COUNTER *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_DELETE_COUNTER_COUNT);
	KS_SUB(KS_CURRENT_COUNT, c->c);

	DeleteLock(c->lock);
	Free(c);
}

// Get the count value
UINT Count(COUNTER *c)
{
	UINT ret;
	// Validate arguments
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		ret = c->c;
	}
	Unlock(c->lock);

	return ret;
}

// Increment
UINT Inc(COUNTER *c)
{
	UINT ret;
	// Validate arguments
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		c->c++;
		ret = c->c;
	}
	Unlock(c->lock);

	// KS
	KS_INC(KS_INC_COUNT);
	KS_INC(KS_CURRENT_COUNT);

	return ret;
}

// Decrement
UINT Dec(COUNTER *c)
{
	UINT ret;
	// Validate arguments
	if (c == NULL)
	{
		return 0;
	}
	if (c->Ready == false)
	{
		return 0;
	}

	Lock(c->lock);
	{
		if (c->c != 0)
		{
			c->c--;
			ret = c->c;
		}
		else
		{
			ret = 0;
		}
	}
	Unlock(c->lock);

	// KS
	KS_INC(KS_DEC_COUNT);
	KS_DEC(KS_CURRENT_COUNT);

	return ret;
}


// Release of the reference counter
UINT Release(REF *ref)
{
	UINT c;
	// Validate arguments
	if (ref == NULL)
	{
		return 0;
	}

	// KS
	KS_INC(KS_RELEASE_COUNT);
	KS_DEC(KS_CURRENT_REFED_COUNT);

	c = Dec(ref->c);
	if (c == 0)
	{
		// KS
		KS_DEC(KS_CURRENT_REF_COUNT);
		KS_INC(KS_FREEREF_COUNT);

		DeleteCounter(ref->c);
		ref->c = 0;
		Free(ref);
	}
	return c;
}

// Increase of the reference counter
UINT AddRef(REF *ref)
{
	UINT c;
	// Validate arguments
	if (ref == NULL)
	{
		return 0;
	}

	c = Inc(ref->c);

	// KS
	KS_INC(KS_ADDREF_COUNT);
	KS_INC(KS_CURRENT_REFED_COUNT);

	return c;
}

// Create a reference counter
REF *NewRef()
{
	REF *ref;

	// Memory allocation
	ref = Malloc(sizeof(REF));

	// Create a Counter
	ref->c = NewCounter();

	// Increment only once
	Inc(ref->c);

	// KS
	KS_INC(KS_NEWREF_COUNT);
	KS_INC(KS_CURRENT_REF_COUNT);
	KS_INC(KS_ADDREF_COUNT);
	KS_INC(KS_CURRENT_REFED_COUNT);

	return ref;
}

// Creating an event object
EVENT *NewEvent()
{
	// Memory allocation
	EVENT *e = Malloc(sizeof(EVENT));

	// Reference counter
	e->ref = NewRef();

	// Event initialization
	OSInitEvent(e);

	// KS
	KS_INC(KS_NEWEVENT_COUNT);

	return e;
}

// Release of the event
void ReleaseEvent(EVENT *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	if (Release(e->ref) == 0)
	{
		CleanupEvent(e);
	}
}

// Delete the event
void CleanupEvent(EVENT *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	// Release event
	OSFreeEvent(e);

	// Memory release
	Free(e);

	// KS
	KS_INC(KS_FREEEVENT_COUNT);
}

// Set event
void Set(EVENT *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	OSSetEvent(e);
}

// Wait for event
bool Wait(EVENT *e, UINT timeout)
{
	// Validate arguments
	if (e == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_WAIT_COUNT);

	return OSWaitEvent(e, timeout);
}

// Wait for a event until the cancel flag becomes true
bool WaitEx(EVENT *e, UINT timeout, volatile bool *cancel)
{
	bool dummy_bool = false;
	UINT64 start, giveup;
	// Validate arguments
	if (cancel == NULL)
	{
		cancel = &dummy_bool;
	}

	start = Tick64();

	if (timeout == INFINITE || timeout == 0x7FFFFFFF)
	{
		giveup = 0;
	}
	else
	{
		giveup = start + (UINT64)timeout;
	}

	while (true)
	{
		UINT64 now = Tick64();
		UINT interval_to_giveup = (UINT)(giveup - now);
		if (giveup == 0)
		{
			interval_to_giveup = INFINITE;
		}
		else
		{
			if (now >= giveup)
			{
				// Time-out occurs
				return false;
			}
		}

		interval_to_giveup = MIN(interval_to_giveup, 25);

		if (*cancel)
		{
			// Cancel flag is set to true. Time-out occurs
			return false;
		}

		if (e != NULL)
		{
			if (Wait(e, interval_to_giveup))
			{
				// Event is set
				return true;
			}
		}
		else
		{
			SleepThread(interval_to_giveup);
		}
	}
}




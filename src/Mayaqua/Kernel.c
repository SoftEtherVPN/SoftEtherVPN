// SoftEther VPN Source Code
// Mayaqua Kernel
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Contributors:
// - nattoheaven (https://github.com/nattoheaven)
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// Kernel.c
// System service processing routine

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

#ifndef TM_YEAR_MAX
#define TM_YEAR_MAX         2106
#endif
#ifndef TM_MON_MAX
#define TM_MON_MAX          1
#endif
#ifndef TM_MDAY_MAX
#define TM_MDAY_MAX         7
#endif
#ifndef TM_HOUR_MAX
#define TM_HOUR_MAX         6
#endif
#ifndef TM_MIN_MAX
#define TM_MIN_MAX          28
#endif
#ifndef TM_SEC_MAX
#define TM_SEC_MAX          14
#endif

#define ADJUST_TM(tm_member, tm_carry, modulus) \
	if ((tm_member) < 0){ \
	tm_carry -= (1 - ((tm_member)+1) / (modulus)); \
	tm_member = (modulus-1) + (((tm_member)+1) % (modulus)); \
	} else if ((tm_member) >= (modulus)) { \
	tm_carry += (tm_member) / (modulus); \
	tm_member = (tm_member) % (modulus); \
	}
#define leap(y) (((y) % 4 == 0 && (y) % 100 != 0) || (y) % 400 == 0)
#define nleap(y) (((y) - 1969) / 4 - ((y) - 1901) / 100 + ((y) - 1601) / 400)
#define leapday(m, y) ((m) == 1 && leap (y))
#define monthlen(m, y) (ydays[(m)+1] - ydays[m] + leapday (m, y))
static int ydays[] =
{
	0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365
};

static UINT current_num_thread = 0;



static wchar_t *default_locale_str =
L"- - $ : : $ Sun Mon Tue Wed Thu Fri Sat : : : $ (None)";


static LOCALE current_locale;
LOCK *tick_manual_lock = NULL;
UINT g_zero = 0;

// Get the real-time system timer
UINT TickRealtime()
{
#if	defined(OS_WIN32) || defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC) || defined(CLOCK_HIGHRES) || defined(UNIX_MACOS)
	return Tick() + 1;
#else
	return TickRealtimeManual() + 1;
#endif
}

#ifndef	OS_WIN32

static UINT64 last_manual_tick = 0;
static UINT64 manual_tick_add_value = 0;

// For systems which not have clock_gettime (such as MacOS X)
UINT TickRealtimeManual()
{
	UINT64 ret;
	Lock(tick_manual_lock);
	{
		ret = TickGetRealtimeTickValue64();

		if (last_manual_tick != 0 && (last_manual_tick > ret))
		{
			manual_tick_add_value += (last_manual_tick - ret);
		}

		last_manual_tick = ret;
	}
	Unlock(tick_manual_lock);

	return (UINT)(ret + manual_tick_add_value);
}

// Returns a appropriate value from the current time
UINT64 TickGetRealtimeTickValue64()
{
	struct timeval tv;
	struct timezone tz;
	UINT64 ret;

	memset(&tv, 0, sizeof(tv));
	memset(&tz, 0, sizeof(tz));

	gettimeofday(&tv, &tz);

	ret = (UINT64)tv.tv_sec * 1000ULL + (UINT64)tv.tv_usec / 1000ULL;

	return ret;
}

#endif	// OS_WIN32

// Creating a thread list
LIST *NewThreadList()
{
	LIST *o = NewList(NULL);

	return o;
}

// Remove the thread from the thread list
void DelThreadFromThreadList(LIST *o, THREAD *t)
{
	// Validate arguments
	if (o == NULL || t == NULL)
	{
		return;
	}

	LockList(o);
	{
		if (Delete(o, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(o);
}

// Add the thread to the thread list
void AddThreadToThreadList(LIST *o, THREAD *t)
{
	// Validate arguments
	if (o == NULL || t == NULL)
	{
		return;
	}

	LockList(o);
	{
		if (IsInList(o, t) == false)
		{
			AddRef(t->ref);

			Add(o, t);
		}
	}
	UnlockList(o);
}

// Maintain thread list
void MainteThreadList(LIST *o)
{
	UINT i;
	LIST *delete_list = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			THREAD *t = LIST_DATA(o, i);

			if (t->Stopped)
			{
				if (delete_list == NULL)
				{
					delete_list = NewListFast(NULL);
				}

				Add(delete_list, t);
			}
		}

		if (delete_list != NULL)
		{
			for (i = 0;i < LIST_NUM(delete_list);i++)
			{
				THREAD *t = LIST_DATA(delete_list, i);

				ReleaseThread(t);

				Delete(o, t);
			}

			ReleaseList(delete_list);
		}
	}
	UnlockList(o);
}

// Wait until all threads in the thread list will be stopped
void WaitAllThreadsWillBeStopped(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	while (LIST_NUM(o) != 0)
	{
		SleepThread(100);
	}
}

// Stop all the threads in the thread list
void StopThreadList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			THREAD *t = LIST_DATA(o, i);

			WaitThread(t, INFINITE);
		}
	}
	UnlockList(o);
}

// Release the thread list
void FreeThreadList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			THREAD *t = LIST_DATA(o, i);

			WaitThread(t, INFINITE);

			ReleaseThread(t);
		}

		DeleteAll(o);
	}
	UnlockList(o);

	ReleaseList(o);
}

// Get the home directory
void GetHomeDirW(wchar_t *path, UINT size)
{
	// Validate arguments
	if (path == NULL)
	{
		return;
	}

	if (GetEnvW(L"HOME", path, size) == false)
	{
		wchar_t drive[MAX_SIZE];
		wchar_t hpath[MAX_SIZE];
		if (GetEnvW(L"HOMEDRIVE", drive, sizeof(drive)) &&
			GetEnvW(L"HOMEPATH", hpath, sizeof(hpath)))
		{
			UniFormat(path, sizeof(path), L"%s%s", drive, hpath);
		}
		else
		{
#ifdef	OS_WIN32
			Win32GetCurrentDirW(path, size);
#else	// OS_WIN32
			UnixGetCurrentDirW(path, size);
#endif	// OS_WIN32
		}
	}
}
void GetHomeDir(char *path, UINT size)
{
	// Validate arguments
	if (path == NULL)
	{
		return;
	}

	if (GetEnv("HOME", path, size) == false)
	{
		char drive[MAX_SIZE];
		char hpath[MAX_SIZE];
		if (GetEnv("HOMEDRIVE", drive, sizeof(drive)) &&
			GetEnv("HOMEPATH", hpath, sizeof(hpath)))
		{
			Format(path, sizeof(path), "%s%s", drive, hpath);
		}
		else
		{
#ifdef	OS_WIN32
			Win32GetCurrentDir(path, size);
#else	// OS_WIN32
			UnixGetCurrentDir(path, size);
#endif	// OS_WIN32
		}
	}
}

// Get the environment variable string
bool GetEnv(char *name, char *data, UINT size)
{
	char *ret;
	// Validate arguments
	if (name == NULL || data == NULL)
	{
		return false;
	}

	StrCpy(data, size, "");

	ret = getenv(name);
	if (ret == NULL)
	{
		return false;
	}

	StrCpy(data, size, ret);

	return true;
}
bool GetEnvW(wchar_t *name, wchar_t *data, UINT size)
{
#ifdef	OS_WIN32
	return GetEnvW_ForWin32(name, data, size);
#else	// OS_WIN32
	return GetEnvW_ForUnix(name, data, size);
#endif	// OS_WIN32
}

#ifdef	OS_WIN32
bool GetEnvW_ForWin32(wchar_t *name, wchar_t *data, UINT size)
{
	wchar_t *ret;
	// Validate arguments
	if (name == NULL || data == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		bool ret;
		char *name_a = CopyUniToStr(name);
		char data_a[MAX_SIZE];

		ret = GetEnv(name_a, data_a, sizeof(data_a));

		if (ret)
		{
			StrToUni(data, size, data_a);
		}

		Free(name_a);

		return ret;
	}

	UniStrCpy(data, size, L"");

	ret = _wgetenv(name);
	if (ret == NULL)
	{
		return false;
	}

	UniStrCpy(data, size, ret);

	return true;
}

#endif	// OS_WIN32

#ifdef	OS_UNIX

bool GetEnvW_ForUnix(wchar_t *name, wchar_t *data, UINT size)
{
	char *name_a;
	bool ret;
	char data_a[MAX_SIZE];
	// Validate arguments
	if (name == NULL || data == NULL)
	{
		return false;
	}

	name_a = CopyUniToUtf(name);

	ret = GetEnv(name_a, data_a, sizeof(data_a));

	if (ret)
	{
		UtfToUni(data, size, data_a);
	}

	Free(name_a);

	return ret;
}

#endif	// OS_UNIX

// Get the memory information
void GetMemInfo(MEMINFO *info)
{
	OSGetMemInfo(info);
}

// Start the single-instance
INSTANCE *NewSingleInstance(char *instance_name)
{
	return NewSingleInstanceEx(instance_name, false);
}
INSTANCE *NewSingleInstanceEx(char *instance_name, bool user_local)
{
	char name[MAX_SIZE];
	INSTANCE *ret;
	void *data;

	if (instance_name != NULL)
	{
		if (user_local == false)
		{
			HashInstanceName(name, sizeof(name), instance_name);
		}
		else
		{
			HashInstanceNameLocal(name, sizeof(name), instance_name);
		}

		data = OSNewSingleInstance(name);
	}
	else
	{
		data = OSNewSingleInstance(NULL);
	}

	if (data == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(INSTANCE));
	if (instance_name != NULL)
	{
		ret->Name = CopyStr(instance_name);
	}

	ret->pData = data;

	return ret;
}

// Release of single instance
void FreeSingleInstance(INSTANCE *inst)
{
	// Validate arguments
	if (inst == NULL)
	{
		return;
	}

	OSFreeSingleInstance(inst->pData);

	if (inst->Name != NULL)
	{
		Free(inst->Name);
	}
	Free(inst);
}

// Hashing the instance name
void HashInstanceName(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	char key[11];
	// Validate arguments
	if (name == NULL || instance_name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), instance_name);
	Trim(tmp);
	StrUpper(tmp);

	Hash(hash, tmp, StrLen(tmp), SHA1_SIZE);
	BinToStr(key, sizeof(key), hash, 5);
	key[10] = 0;

	Format(name, size, "VPN-%s", key);

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2 ||
			GetOsInfo()->OsType == OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER)
		{
			StrCpy(tmp, sizeof(tmp), name);
			Format(name, size, "Global\\%s", tmp);
		}
	}
}
void HashInstanceNameLocal(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	char key[11];
	// Validate arguments
	if (name == NULL || instance_name == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), instance_name);
	Trim(tmp);
	StrUpper(tmp);

	Hash(hash, tmp, StrLen(tmp), SHA1_SIZE);
	BinToStr(key, sizeof(key), hash, 5);
	key[10] = 0;

	Format(name, size, "VPN-%s", key);

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2 ||
			GetOsInfo()->OsType == OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER)
		{
			StrCpy(tmp, sizeof(tmp), name);
			Format(name, size, "Local\\%s", tmp);
		}
	}
}

// Run the process
bool Run(char *filename, char *arg, bool hide, bool wait)
{
	// Validate arguments
	if (filename == NULL)
	{
		return false;
	}

	return OSRun(filename, arg, hide, wait);
}
bool RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	// Validate arguments
	if (filename == NULL)
	{
		return false;
	}

	return OSRunW(filename, arg, hide, wait);
}

// Date and time related functions
void GetDateTimeStr64Uni(wchar_t *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	if (str == NULL)
	{
		return;
	}

	GetDateTimeStr64(tmp, sizeof(tmp), sec64);
	StrToUni(str, size, tmp);
}
void GetDateTimeStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStr(str, size, &st);
}
void GetDateTimeStrMilli64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrMilli(str, size, &st);
}
void GetDateTimeStrMilli64ForFileName(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrMilliForFileName(str, size, &st);
}
void GetDateTimeStrMilliForFileName(char *str, UINT size, SYSTEMTIME *tm)
{
	Format(str, size, "%04u%02u%02u_%02u%02u%02u",
		tm->wYear, tm->wMonth, tm->wDay, tm->wHour, tm->wMinute, tm->wSecond);
}
void GetDateStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStr(str, size, &st);
}
void GetDateTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateTimeStrEx(str, size, &st, locale);
}
void GetTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStrEx(str, size, &st, locale);
}
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	SYSTEMTIME st;
	if (locale == NULL)
	{
		locale = &current_locale;
	}
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		UniStrCpy(str, size, locale->Unknown);
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetDateStrEx(str, size, &st, locale);
}
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStrMilli(str, size, &st);
}
void GetTimeStr64(char *str, UINT size, UINT64 sec64)
{
	SYSTEMTIME st;
	if (sec64 == 0 || SystemToLocal64(sec64) == 0 || LocalToSystem64(sec64) == 0)
	{
		StrCpy(str, size, "(Unknown)");
		return;
	}
	UINT64ToSystem(&st, sec64);
	GetTimeStr(str, size, &st);
}

// Convert to a time to be used safely in the current POSIX implementation
UINT64 SafeTime64(UINT64 sec64)
{
	return MAKESURE(sec64, 0, 2115947647000ULL);
}

// Thread pool
static SK *thread_pool = NULL;
static COUNTER *thread_count = NULL;

// Initialization of thread pool
void InitThreading()
{
	thread_pool = NewSk();
	thread_count = NewCounter();
}

// Release of thread pool
void FreeThreading()
{
	while (true)
	{
		if (Count(thread_count) == 0)
		{
			break;
		}

		SleepThread(25);
	}

	while (true)
	{
		THREAD_POOL_DATA *pd;
		THREAD *t = Pop(thread_pool);

		if (t == NULL)
		{
			break;
		}

		pd = (THREAD_POOL_DATA *)t->param;

		pd->ThreadProc = NULL;
		Set(pd->Event);

		WaitThreadInternal(t);

		pd = (THREAD_POOL_DATA *)t->param;
		ReleaseEvent(pd->Event);
		ReleaseEvent(pd->InitFinishEvent);

		ReleaseThreadInternal(t);

		Free(pd);
	}

	ReleaseSk(thread_pool);

	DeleteCounter(thread_count);
	thread_count = NULL;
}

// Thread pool procedure
void ThreadPoolProc(THREAD *t, void *param)
{
	THREAD_POOL_DATA *pd;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	pd = (THREAD_POOL_DATA *)param;

	NoticeThreadInitInternal(t);

	while (true)
	{
		THREAD *thread;
		UINT i, num;
		EVENT **ee;

		// Wait for the next job
		Wait(pd->Event, INFINITE);

		if (pd->ThreadProc == NULL)
		{
			// Stop the pool thread
			break;
		}

		thread = pd->Thread;
		thread->ThreadId = ThreadId();

		// Initialization is completed
		Set(pd->InitFinishEvent);

		// Set the thread name
		if (thread->Name != NULL)
		{
			SetThreadName(thread->ThreadId, thread->Name, thread->param);
		}
		else
		{
			SetThreadName(thread->ThreadId, "Unknown", 0);
		}

		// Run the thread procedure
		pd->ThreadProc(pd->Thread, thread->param);

		// Set the thread name
		SetThreadName(thread->ThreadId, NULL, 0);

		pd->Thread->Stopped = true;

		thread->PoolHalting = true;

		// Set the waiting event list
		LockList(thread->PoolWaitList);
		{
			num = LIST_NUM(thread->PoolWaitList);
			ee = ToArray(thread->PoolWaitList);

			DeleteAll(thread->PoolWaitList);
		}
		UnlockList(thread->PoolWaitList);

		for (i = 0;i < num;i++)
		{
			EVENT *e = ee[i];

			Set(e);
			ReleaseEvent(e);
		}

		Free(ee);

		while (true)
		{
			if (Count(thread->ref->c) <= 1)
			{
				break;
			}

			Wait(thread->release_event, 256);
		}

		ReleaseThread(thread);

#ifdef	OS_WIN32
		// For Win32: Recover the priority of the thread
		MsRestoreThreadPriority();
#endif	// OS_WIN32

		// Register the thread itself to the thread pool
		LockSk(thread_pool);
		{
			Push(thread_pool, t);
		}
		UnlockSk(thread_pool);

		Dec(thread_count);
	}
}

// Set the thread name
void SetThreadName(UINT thread_id, char *name, void *param)
{
#ifdef	OS_WIN32
	if (IsDebug())
	{
		char tmp[MAX_SIZE];

		if (name == NULL)
		{
			strcpy(tmp, "idle");
		}
		else
		{
			sprintf(tmp, "%s (0x%x)", name, (UINT)param);
		}

		Win32SetThreadName(thread_id, tmp);
	}
#else	// OS_WIN32
#ifdef	_DEBUG
#ifdef	PR_SET_NAME
	char tmp[MAX_SIZE];

	if (name == NULL)
	{
		strcpy(tmp, "idle");
	}
	else
	{
		sprintf(tmp, "%s (%p)", name, param);
	}

	tmp[15] = 0;

	prctl(PR_SET_NAME, (unsigned long)tmp, 0, 0, 0);
#endif	// PR_SET_NAME
#endif	// _DEBUG
#endif	// OS_WIN32
}

// Do Nothing
UINT DoNothing()
{
	return g_zero;
}

// Thread creation (pool)
THREAD *NewThreadNamed(THREAD_PROC *thread_proc, void *param, char *name)
{
	THREAD *host = NULL;
	THREAD_POOL_DATA *pd = NULL;
	THREAD *ret;
	bool new_thread = false;
	// Validate arguments
	if (thread_proc == NULL)
	{
		return NULL;
	}

	if (IsTrackingEnabled() == false)
	{
		DoNothing();
	}

	Inc(thread_count);

	LockSk(thread_pool);
	{
		// Examine whether there is a thread that is currently vacant in the pool
		host = Pop(thread_pool);
	}
	UnlockSk(thread_pool);

	if (host == NULL)
	{
		// Create a new thread because a vacant thread is not found
		pd = ZeroMalloc(sizeof(THREAD_POOL_DATA));
		pd->Event = NewEvent();
		pd->InitFinishEvent = NewEvent();
		host = NewThreadInternal(ThreadPoolProc, pd);
		WaitThreadInitInternal(host);

		new_thread = true;
	}
	else
	{
		pd = (THREAD_POOL_DATA *)host->param;
	}

	// Creating a thread pool
	ret = ZeroMalloc(sizeof(THREAD));
	ret->ref = NewRef();
	ret->thread_proc = thread_proc;
	ret->param = param;
	ret->pData = NULL;
	ret->init_finished_event = NewEvent();
	ret->PoolThread = true;
	ret->PoolWaitList = NewList(NULL);
	ret->PoolHostThread = host;
	ret->release_event = NewEvent();

	if (IsEmptyStr(name) == false)
	{
		ret->Name = CopyStr(name);
	}

	// Run
	pd->ThreadProc = thread_proc;
	pd->Thread = ret;
	AddRef(ret->ref);

	Set(pd->Event);

	Wait(pd->InitFinishEvent, INFINITE);

	current_num_thread++;

//	Debug("current_num_thread = %u\n", current_num_thread);

	return ret;
}

// Clean up of thread (pool)
void CleanupThread(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	ReleaseEvent(t->init_finished_event);
	ReleaseEvent(t->release_event);
	ReleaseList(t->PoolWaitList);

	if (t->Name != NULL)
	{
		Free(t->Name);
	}

	Free(t);

	current_num_thread--;
	//Debug("current_num_thread = %u\n", current_num_thread);
}

// Release thread (pool)
void ReleaseThread(THREAD *t)
{
	UINT ret;
	EVENT *e;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	e = t->release_event;
	if (e != NULL)
	{
		AddRef(e->ref);
	}

	ret = Release(t->ref);
	Set(e);

	ReleaseEvent(e);

	if (ret == 0)
	{
		CleanupThread(t);
	}
}

// Notify the completion of the thread initialization (pool)
void NoticeThreadInit(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// Notification
	Set(t->init_finished_event);
}

// Wait the completion of the thread initialization (pool)
void WaitThreadInit(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_WAITFORTHREAD_COUNT);

	// Wait
	Wait(t->init_finished_event, INFINITE);
}

// Wait for the termination of the thread (pool)
bool WaitThread(THREAD *t, UINT timeout)
{
	bool ret = false;
	EVENT *e = NULL;
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}

	LockList(t->PoolWaitList);
	{
		if (t->PoolHalting)
		{
			// Has already been stopped
			ret = true;
		}
		else
		{
			// Register the completion notifying event to the list
			e = NewEvent();
			AddRef(e->ref);
			Insert(t->PoolWaitList, e);
		}
	}
	UnlockList(t->PoolWaitList);

	if (e != NULL)
	{
		// Wait Event
		ret = Wait(e, timeout);

		LockList(t->PoolWaitList);
		{
			if (Delete(t->PoolWaitList, e))
			{
				ReleaseEvent(e);
			}
		}
		UnlockList(t->PoolWaitList);

		ReleaseEvent(e);
	}

	return ret;
}

// Get Thread ID
UINT ThreadId()
{
	return OSThreadId();
}

// Creating a thread
THREAD *NewThreadInternal(THREAD_PROC *thread_proc, void *param)
{
	THREAD *t;
	UINT retry = 0;
	// Validate arguments
	if (thread_proc == NULL)
	{
		return NULL;
	}

	// Initialize Thread object
	t = ZeroMalloc(sizeof(THREAD));
	t->init_finished_event = NewEvent();

	t->param = param;
	t->ref = NewRef();
	t->thread_proc = thread_proc;

	// Wait until the OS to initialize the thread
	while (true)
	{
		if ((retry++) > 60)
		{
			printf("\n\n*** error: new thread create failed.\n\n");
			AbortExit();
		}
		if (OSInitThread(t))
		{
			break;
		}
		SleepThread(500);
	}

	// KS
	KS_INC(KS_NEWTHREAD_COUNT);

	return t;
}

// Release of thread
void ReleaseThreadInternal(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (Release(t->ref) == 0)
	{
		CleanupThreadInternal(t);
	}
}

// Clean up of the thread
void CleanupThreadInternal(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// Release of the thread
	OSFreeThread(t);

	// Release the event
	ReleaseEvent(t->init_finished_event);
	// Memory release
	Free(t);

	// KS
	KS_INC(KS_FREETHREAD_COUNT);
}

// Wait for the termination of the thread
bool WaitThreadInternal(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}

	return OSWaitThread(t);
}

// Notify that the thread initialization is complete
void NoticeThreadInitInternal(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// Notify
	Set(t->init_finished_event);
}

// Wait for completion of thread initialization
void WaitThreadInitInternal(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_WAITFORTHREAD_COUNT);

	// Wait
	Wait(t->init_finished_event, INFINITE);
}

// Get the date and time string by using the locale information
void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// Validate arguments
	if (str == NULL || st == NULL)
	{
		return;
	}

	GetDateStrEx(tmp1, sizeof(tmp1), st, locale);
	GetTimeStrEx(tmp2, sizeof(tmp2), st, locale);
	UniFormat(str, size, L"%s %s", tmp1, tmp2);
}

// Get the time string by using the locale information
void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t *tag = L"%02u%s%02u%s%02u%s";
	// Validate arguments
	if (str == NULL || st == NULL)
	{
		return;
	}

	if (_GETLANG() == SE_LANG_JAPANESE || _GETLANG() == SE_LANG_CHINESE_ZH)
	{
		tag = L"%2u%s%2u%s%2u%s";
	}

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
		tag,
		st->wHour, locale->HourStr,
		st->wMinute, locale->MinuteStr,
		st->wSecond, locale->SecondStr);
}

// Get a date string by using the locale information
void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale)
{
	wchar_t *tag = L"%04u%s%02u%s%02u%s (%s)";
	// Validate arguments
	if (str == NULL || st == NULL)
	{
		return;
	}

	if (_GETLANG() == SE_LANG_JAPANESE || _GETLANG() == SE_LANG_CHINESE_ZH)
	{
		tag = L"%4u%s%2u%s%2u%s(%s)";
	}

	locale = (locale != NULL ? locale : &current_locale);
	UniFormat(str, size,
		tag,
		st->wYear, locale->YearStr,
		st->wMonth, locale->MonthStr,
		st->wDay, locale->DayStr,
		locale->DayOfWeek[st->wDayOfWeek]);
}

// Get the time string to milliseconds (for example, 12:34:56.789)
void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st)
{
	// Validate arguments
	if (st == NULL || str == NULL)
	{
		return;
	}

	Format(str, size, "%02u:%02u:%02u.%03u",
		st->wHour, st->wMinute, st->wSecond, st->wMilliseconds);
}

// Get the time string (for example, 12:34:56)
void GetTimeStr(char *str, UINT size, SYSTEMTIME *st)
{
	// Validate arguments
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%02u:%02u:%02u",
		st->wHour, st->wMinute, st->wSecond);
}

// Get the date string (example: 2004/07/23)
void GetDateStr(char *str, UINT size, SYSTEMTIME *st)
{
	// Validate arguments
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u",
		st->wYear, st->wMonth, st->wDay);
}

// Get the date and time string (example: 2004/07/23 12:34:56)
void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st)
{
	// Validate arguments
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u %02u:%02u:%02u",
		st->wYear, st->wMonth, st->wDay,
		st->wHour, st->wMinute, st->wSecond);
}

// Get the date and time string in milliseconds (example: 2004/07/23 12:34:56.789)
void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st)
{
	// Validate arguments
	if (str == NULL || st == NULL)
	{
		return;
	}

	Format(str, size, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
		st->wYear, st->wMonth, st->wDay,
		st->wHour, st->wMinute, st->wSecond,
		st->wMilliseconds);
}

// Get the time string
void GetSpanStr(char *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), "");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
	{
		Format(tmp, sizeof(tmp), "%u:", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)));
	}

	Format(tmp, sizeof(tmp), "%s%02u:%02u:%02u", tmp,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60)) / 1000);

	Trim(tmp);
	StrCpy(str, size, tmp);
}

// Get the time string (in milliseconds)
void GetSpanStrMilli(char *str, UINT size, UINT64 sec64)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), "");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
	{
		Format(tmp, sizeof(tmp), "%u:", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)));
	}

	Format(tmp, sizeof(tmp), "%s%02u:%02u:%02u.%03u", tmp,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
		(UINT)(sec64 % (UINT64)(1000 * 60)) / 1000,
		(UINT)(sec64 % (UINT64)(1000)));

	Trim(tmp);
	StrCpy(str, size, tmp);
}

// Get the time string (extended)
void GetSpanStrEx(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	locale = (locale != NULL ? locale : &current_locale);

	UniStrCpy(tmp, sizeof(tmp), L"");
	if (sec64 >= (UINT64)(1000 * 3600 * 24))
	{
		UniFormat(tmp, sizeof(tmp), L"%u%s ", (UINT)(sec64 / (UINT64)(1000 * 3600 * 24)),
			locale->SpanDay);
	}

	UniFormat(tmp, sizeof(tmp), L"%s%u%s %02u%s %02u%s", tmp,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
		locale->SpanHour,
		(UINT)(sec64 % (UINT64)(1000 * 60 * 60)) / (1000 * 60),
		locale->SpanMinute,
		(UINT)(sec64 % (UINT64)(1000 * 60)) / 1000,
		locale->SpanSecond);

	UniTrim(tmp);
	UniStrCpy(str, size, tmp);
}

// Get the current locale information
void GetCurrentLocale(LOCALE *locale)
{
	// Validate arguments
	if (locale == NULL)
	{
		return;
	}

	Copy(locale, &current_locale, sizeof(LOCALE));
}

// Set the locale information
void SetLocale(wchar_t *str)
{
	wchar_t *set_locale_str;
	LOCALE tmp;

	if (str != NULL)
	{
		set_locale_str = str;
	}
	else
	{
		set_locale_str = default_locale_str;
	}

	if (LoadLocale(&tmp, set_locale_str) == false)
	{
		if (LoadLocale(&tmp, default_locale_str) == false)
		{
			return;
		}
	}

	Copy(&current_locale, &tmp, sizeof(LOCALE));
}

#define	COPY_LOCALE_STR(dest, size, src)	UniStrCpy(dest, size, UniStrCmp(src, L"$") == 0 ? L"" : src)

// Read the locale information
bool LoadLocale(LOCALE *locale, wchar_t *str)
{
	UNI_TOKEN_LIST *tokens;
	UINT i;
	// Validate arguments
	if (locale == NULL || str == NULL)
	{
		return false;
	}

	// Analysis of the token
	tokens = UniParseToken(str, L" ");
	if (tokens->NumTokens != 18)
	{
		UniFreeToken(tokens);
		return false;
	}

	// Set to the structure
	Zero(locale, sizeof(LOCALE));
	COPY_LOCALE_STR(locale->YearStr, sizeof(locale->YearStr), tokens->Token[0]);
	COPY_LOCALE_STR(locale->MonthStr, sizeof(locale->MonthStr), tokens->Token[1]);
	COPY_LOCALE_STR(locale->DayStr, sizeof(locale->DayStr), tokens->Token[2]);
	COPY_LOCALE_STR(locale->HourStr, sizeof(locale->HourStr), tokens->Token[3]);
	COPY_LOCALE_STR(locale->MinuteStr, sizeof(locale->MinuteStr), tokens->Token[4]);
	COPY_LOCALE_STR(locale->SecondStr, sizeof(locale->SecondStr), tokens->Token[5]);

	for (i = 0;i < 7;i++)
	{
		COPY_LOCALE_STR(locale->DayOfWeek[i], sizeof(locale->DayOfWeek[i]),
			tokens->Token[6 + i]);
	}

	COPY_LOCALE_STR(locale->SpanDay, sizeof(locale->SpanDay), tokens->Token[13]);
	COPY_LOCALE_STR(locale->SpanHour, sizeof(locale->SpanHour), tokens->Token[14]);
	COPY_LOCALE_STR(locale->SpanMinute, sizeof(locale->SpanMinute), tokens->Token[15]);
	COPY_LOCALE_STR(locale->SpanSecond, sizeof(locale->SpanSecond), tokens->Token[16]);

	COPY_LOCALE_STR(locale->Unknown, sizeof(locale->Unknown), tokens->Token[17]);

	UniFreeToken(tokens);
	return true;
}

// Convert SYSTEMTIME into DOS date
USHORT SystemToDosDate(SYSTEMTIME *st)
{
	return (USHORT)(
		((UINT)(st->wYear - 1980) << 9) |
		((UINT)st->wMonth<< 5) |
		(UINT)st->wDay);
}
USHORT System64ToDosDate(UINT64 i)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, i);
	return SystemToDosDate(&st);
}

// Convert SYSTEMTIME into DOS time
USHORT SystemToDosTime(SYSTEMTIME *st)
{
	return (USHORT)(
		((UINT)st->wHour << 11) |
		((UINT)st->wMinute << 5) |
		((UINT)st->wSecond >> 1));
}
USHORT System64ToDosTime(UINT64 i)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, i);
	return SystemToDosTime(&st);
}

// Convert the tm to the SYSTEMTIME
void TmToSystem(SYSTEMTIME *st, struct tm *t)
{
	struct tm tmp;
	// Validate arguments
	if (st == NULL || t == NULL)
	{
		return;
	}

	Copy(&tmp, t, sizeof(struct tm));
	NormalizeTm(&tmp);

	Zero(st, sizeof(SYSTEMTIME));
	st->wYear = MAKESURE(tmp.tm_year + 1900, 1970, 2037);
	st->wMonth = MAKESURE(tmp.tm_mon + 1, 1, 12);
	st->wDay = MAKESURE(tmp.tm_mday, 1, 31);
	st->wDayOfWeek = MAKESURE(tmp.tm_wday, 0, 6);
	st->wHour = MAKESURE(tmp.tm_hour, 0, 23);
	st->wMinute = MAKESURE(tmp.tm_min, 0, 59);
	st->wSecond = MAKESURE(tmp.tm_sec, 0, 59);
	st->wMilliseconds = 0;
}

// Convert the SYSTEMTIME to tm
void SystemToTm(struct tm *t, SYSTEMTIME *st)
{
	// Validate arguments
	if (t == NULL || st == NULL)
	{
		return;
	}

	Zero(t, sizeof(struct tm));
	t->tm_year = MAKESURE(st->wYear, 1970, 2037) - 1900;
	t->tm_mon = MAKESURE(st->wMonth, 1, 12) - 1;
	t->tm_mday = MAKESURE(st->wDay, 1, 31);
	t->tm_hour = MAKESURE(st->wHour, 0, 23);
	t->tm_min = MAKESURE(st->wMinute, 0, 59);
	t->tm_sec = MAKESURE(st->wSecond, 0, 59);

	t->tm_isdst = -1;
	NormalizeTm(t);
}

// Convert the time_t to SYSTEMTIME
void TimeToSystem(SYSTEMTIME *st, time_t t)
{
	struct tm tmp;
	// Validate arguments
	if (st == NULL)
	{
		return;
	}

	TimeToTm(&tmp, t);
	TmToSystem(st, &tmp);
}

// Convert the time_t to 64-bit SYSTEMTIME
UINT64 TimeToSystem64(time_t t)
{
	SYSTEMTIME st;

	TimeToSystem(&st, t);

	return SystemToUINT64(&st);
}

// Convert the SYSTEMTIME to time_t
time_t SystemToTime(SYSTEMTIME *st)
{
	struct tm t;
	// Validate arguments
	if (st == NULL)
	{
		return 0;
	}

	SystemToTm(&t, st);
	return TmToTime(&t);
}

// Convert a 64-bit SYSTEMTIME to a time_t
time_t System64ToTime(UINT64 i)
{
	SYSTEMTIME st;

	UINT64ToSystem(&st, i);

	return SystemToTime(&st);
}

// Convert the tm to time_t
time_t TmToTime(struct tm *t)
{
	time_t tmp;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	tmp = c_mkgmtime(t);
	if (tmp == (time_t)-1)
	{
		return 0;
	}
	return tmp;
}

// Convert time_t to tm
void TimeToTm(struct tm *t, time_t time)
{
	struct tm *ret;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

#ifndef	OS_UNIX
	ret = gmtime(&time);
#else	// OS_UNIX
	ret = malloc(sizeof(struct tm));
	memset(ret, 0, sizeof(struct tm));
	gmtime_r(&time, ret);
#endif	// OS_UNIX

	if (ret == NULL)
	{
		Zero(t, sizeof(struct tm));
	}
	else
	{
		Copy(t, ret, sizeof(struct tm));
	}

#ifdef	OS_UNIX
	free(ret);
#endif	// OS_UNIX
}

// Normalize the tm
void NormalizeTm(struct tm *t)
{
	struct tm *ret;
	time_t tmp;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	tmp = c_mkgmtime(t);
	if (tmp == (time_t)-1)
	{
		return;
	}

#ifndef	OS_UNIX
	ret = gmtime(&tmp);
#else	// OS_UNIX
	ret = malloc(sizeof(struct tm));
	memset(ret, 0, sizeof(struct tm));
	gmtime_r(&tmp, ret);
#endif	// OS_UNIX

	if (ret == NULL)
	{
		Zero(t, sizeof(struct tm));
	}
	else
	{
		Copy(t, ret, sizeof(struct tm));
	}

#ifdef	OS_UNIX
	free(ret);
#endif	// OS_UNIX
}

// Normalize the SYSTEMTIME
void NormalizeSystem(SYSTEMTIME *st)
{
	UINT64 sec64;
	// Validate arguments
	if (st == NULL)
	{
		return;
	}

	sec64 = SystemToUINT64(st);
	UINT64ToSystem(st, sec64);
}

// Convert a 64-bit local time to a system time
UINT64 LocalToSystem64(UINT64 t)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	LocalToSystem(&st, &st);
	return SystemToUINT64(&st);
}

// Convert the 64bit system time to local time
UINT64 SystemToLocal64(UINT64 t)
{
	SYSTEMTIME st;
	UINT64ToSystem(&st, t);
	SystemToLocal(&st, &st);
	return SystemToUINT64(&st);
}

// Convert local time to system time
void LocalToSystem(SYSTEMTIME *system, SYSTEMTIME *local)
{
	UINT64 sec64;
	// Validate arguments
	if (local == NULL || system == NULL)
	{
		return;
	}

	sec64 = (UINT64)((INT64)SystemToUINT64(local) - GetTimeDiffEx(local, true));
	UINT64ToSystem(system, sec64);
}

// Convert the system time to local time
void SystemToLocal(SYSTEMTIME *local, SYSTEMTIME *system)
{
	UINT64 sec64;
	// Validate arguments
	if (local == NULL || system == NULL)
	{
		return;
	}

	sec64 = (UINT64)((INT64)SystemToUINT64(system) + GetTimeDiffEx(system, false));
	UINT64ToSystem(local, sec64);
}

// Get the time difference between the local time and the system time based on the specified time
INT64 GetTimeDiffEx(SYSTEMTIME *basetime, bool local_time)
{
	time_t tmp;
	struct tm t1, t2;
	SYSTEMTIME snow;
	struct tm now;
	SYSTEMTIME s1, s2;
	INT64 ret;

	Copy(&snow, basetime, sizeof(SYSTEMTIME));

	SystemToTm(&now, &snow);
	if (local_time == false)
	{
		tmp = c_mkgmtime(&now);
	}
	else
	{
		tmp = mktime(&now);
	}

	if (tmp == (time_t)-1)
	{
		return 0;
	}

#ifndef	OS_UNIX
	Copy(&t1, localtime(&tmp), sizeof(struct tm));
	Copy(&t2, gmtime(&tmp), sizeof(struct tm));
#else	// OS_UNIX
	localtime_r(&tmp, &t1);
	gmtime_r(&tmp, &t2);
#endif	// OS_UNIX

	TmToSystem(&s1, &t1);
	TmToSystem(&s2, &t2);

	ret = (INT)SystemToUINT64(&s1) - (INT)SystemToUINT64(&s2);

	return ret;
}

// Get the time difference between the local time and system time
INT64 GetTimeDiff()
{
	time_t tmp;
	struct tm t1, t2;
	SYSTEMTIME snow;
	struct tm now;
	SYSTEMTIME s1, s2;
	INT64 ret;

	static INT64 cache = INFINITE;

	if (cache != INFINITE)
	{
		// Returns the cache data after measured once
		return cache;
	}

	SystemTime(&snow);
	SystemToTm(&now, &snow);
	tmp = c_mkgmtime(&now);
	if (tmp == (time_t)-1)
	{
		return 0;
	}

#ifndef	OS_UNIX
	Copy(&t1, localtime(&tmp), sizeof(struct tm));
	Copy(&t2, gmtime(&tmp), sizeof(struct tm));
#else	// OS_UNIX
	localtime_r(&tmp, &t1);
	gmtime_r(&tmp, &t2);
#endif	// OS_UNIX

	TmToSystem(&s1, &t1);
	TmToSystem(&s2, &t2);

	cache = ret = (INT)SystemToUINT64(&s1) - (INT)SystemToUINT64(&s2);

	return ret;
}

// Convert UINT64 to the SYSTEMTIME
void UINT64ToSystem(SYSTEMTIME *st, UINT64 sec64)
{
	UINT64 tmp64;
	UINT sec, millisec;
	time_t time;
	// Validate arguments
	if (st == NULL)
	{
		return;
	}

	sec64 = SafeTime64(sec64 + 32400000ULL);
	tmp64 = sec64 / (UINT64)1000;
	millisec = (UINT)(sec64 - tmp64 * (UINT64)1000);
	sec = (UINT)tmp64;
	time = (time_t)sec;
	TimeToSystem(st, time);
	st->wMilliseconds = (WORD)millisec;
}

// Convert the SYSTEMTIME to UINT64
UINT64 SystemToUINT64(SYSTEMTIME *st)
{
	UINT64 sec64;
	time_t time;
	// Validate arguments
	if (st == NULL)
	{
		return 0;
	}

	time = SystemToTime(st);
	sec64 = (UINT64)time * (UINT64)1000;
	sec64 += st->wMilliseconds;

	return sec64 - 32400000ULL;
}

// Get local time in UINT64
UINT64 LocalTime64()
{
	SYSTEMTIME s;
	LocalTime(&s);
	return SystemToUINT64(&s);
}

// Get the system time in UINT64
UINT64 SystemTime64()
{
	SYSTEMTIME s;
	SystemTime(&s);
	return SystemToUINT64(&s);
}

// Get local time
void LocalTime(SYSTEMTIME *st)
{
	SYSTEMTIME tmp;
	// Validate arguments
	if (st == NULL)
	{
		return;
	}

	SystemTime(&tmp);
	SystemToLocal(st, &tmp);
}

// Get the System Time
void SystemTime(SYSTEMTIME *st)
{
	// Validate arguments
	if (st == NULL)
	{
		return;
	}

	OSGetSystemTime(st);

	// KS
	KS_INC(KS_GETTIME_COUNT);
}

time_t c_mkgmtime(struct tm *tm)
{
	int years, months, days, hours, minutes, seconds;

	years = tm->tm_year + 1900;   /* year - 1900 -> year */
	months = tm->tm_mon;          /* 0..11 */
	days = tm->tm_mday - 1;       /* 1..31 -> 0..30 */
	hours = tm->tm_hour;          /* 0..23 */
	minutes = tm->tm_min;         /* 0..59 */
	seconds = tm->tm_sec;         /* 0..61 in ANSI C. */

	ADJUST_TM(seconds, minutes, 60);
	ADJUST_TM(minutes, hours, 60);
	ADJUST_TM(hours, days, 24);
	ADJUST_TM(months, years, 12);
	if (days < 0)
		do {
			if (--months < 0) {
				--years;
				months = 11;
			}
			days += monthlen(months, years);
		} while (days < 0);
	else
		while (days >= monthlen(months, years)) {
			days -= monthlen(months, years);
			if (++months >= 12) {
				++years;
				months = 0;
			}
		}

		/* Restore adjusted values in tm structure */
		tm->tm_year = years - 1900;
		tm->tm_mon = months;
		tm->tm_mday = days + 1;
		tm->tm_hour = hours;
		tm->tm_min = minutes;
		tm->tm_sec = seconds;

		/* Set `days' to the number of days into the year. */
		days += ydays[months] + (months > 1 && leap (years));
		tm->tm_yday = days;

		/* Now calculate `days' to the number of days since Jan 1, 1970. */
		days = (unsigned)days + 365 * (unsigned)(years - 1970) +
			(unsigned)(nleap (years));
		tm->tm_wday = ((unsigned)days + 4) % 7; /* Jan 1, 1970 was Thursday. */
		tm->tm_isdst = 0;

		if (years < 1970)
			return (time_t)-1;

#if (defined(TM_YEAR_MAX) && defined(TM_MON_MAX) && defined(TM_MDAY_MAX))
#if (defined(TM_HOUR_MAX) && defined(TM_MIN_MAX) && defined(TM_SEC_MAX))
		if (years > TM_YEAR_MAX ||
			(years == TM_YEAR_MAX &&
			(tm->tm_yday > ydays[TM_MON_MAX] + (TM_MDAY_MAX - 1) +
			(TM_MON_MAX > 1 && leap (TM_YEAR_MAX)) ||
			(tm->tm_yday == ydays[TM_MON_MAX] + (TM_MDAY_MAX - 1) +
			(TM_MON_MAX > 1 && leap (TM_YEAR_MAX)) &&
			(hours > TM_HOUR_MAX ||
			(hours == TM_HOUR_MAX &&
			(minutes > TM_MIN_MAX ||
			(minutes == TM_MIN_MAX && seconds > TM_SEC_MAX) )))))))
			return (time_t)-1;
#endif
#endif

		return (time_t)(86400L * (unsigned long)(unsigned)days +
			3600L * (unsigned long)hours +
			(unsigned long)(60 * minutes + seconds));
}

// Get the system timer
UINT Tick()
{
	// KS
	KS_INC(KS_GETTICK_COUNT);
	return OSGetTick();
}

// Sleep thread
void SleepThread(UINT time)
{
	// KS
	KS_INC(KS_SLEEPTHREAD_COUNT);

	OSSleep(time);
}

// Yield
void YieldCpu()
{
	OSYield();
}

// Stop system (abnormal termination)
void AbortExit()
{
#ifdef	OS_WIN32
	_exit(1);
#else	// OS_WIN32

#ifdef	RLIMIT_CORE
	UnixSetResourceLimit(RLIMIT_CORE, 0);
#endif	// RLIMIT_CORE

	abort();
#endif	// OS_WIN32
}


void AbortExitEx(char *msg)
{
	FILE *f;
	// Validate arguments
	if (msg == NULL)
	{
		msg = "Unknown Error";
	}

	f = fopen("abort_error_log.txt", "w");
	if (f != NULL)
	{
		fwrite(msg, 1, strlen(msg), f);
		fclose(f);
	}

	fputs("Fatal Error: ", stdout);
	fputs(msg, stdout);
	fputs("\r\n", stdout);

#ifdef	OS_WIN32
	_exit(1);
#else	// OS_WIN32

#ifdef	RLIMIT_CORE
	UnixSetResourceLimit(RLIMIT_CORE, 0);
#endif	// RLIMIT_CORE

	abort();
#endif	// OS_WIN32
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/

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


#ifndef	KERNEL_H
#define	KERNEL_H

// Memory usage information
struct MEMINFO
{
	UINT64 TotalMemory;
	UINT64 UsedMemory;
	UINT64 FreeMemory;
	UINT64 TotalPhys;
	UINT64 UsedPhys;
	UINT64 FreePhys;
};

// Locale information
struct LOCALE
{
	wchar_t YearStr[16], MonthStr[16], DayStr[16];
	wchar_t HourStr[16], MinuteStr[16], SecondStr[16];
	wchar_t DayOfWeek[7][16];
	wchar_t SpanDay[16], SpanHour[16], SpanMinute[16], SpanSecond[16];
	wchar_t Unknown[32];
};


// Thread procedure
typedef void (THREAD_PROC)(THREAD *thread, void *param);

// Thread
struct THREAD
{
	REF *ref;
	THREAD_PROC *thread_proc;
	void *param;
	void *pData;
	EVENT *init_finished_event;
	void *AppData1, *AppData2, *AppData3;
	UINT AppInt1, AppInt2, AppInt3;
	UINT ThreadId;
	bool PoolThread;
	THREAD *PoolHostThread;
	LIST *PoolWaitList;						// Thread termination waiting list
	volatile bool PoolHalting;				// Thread stopped
	EVENT *release_event;
	bool Stopped;							// Indicates that the operation is Stopped
	char *Name;								// Thread name
};

// Thread pool data
struct THREAD_POOL_DATA
{
	EVENT *Event;						// Waiting Event
	EVENT *InitFinishEvent;				// Initialization is completed event
	THREAD *Thread;						// Threads that are currently assigned
	THREAD_PROC *ThreadProc;			// Thread procedure that is currently assigned
};

// Instance
struct INSTANCE
{
	char *Name;							// Name
	void *pData;						// Data
};

// Create a new thread
#define	NewThread(thread_proc, param) NewThreadNamed((thread_proc), (param), (#thread_proc))

// Function prototype
void SleepThread(UINT time);
THREAD *NewThreadInternal(THREAD_PROC *thread_proc, void *param);
void ReleaseThreadInternal(THREAD *t);
void CleanupThreadInternal(THREAD *t);
void NoticeThreadInitInternal(THREAD *t);
void WaitThreadInitInternal(THREAD *t);
bool WaitThreadInternal(THREAD *t);
THREAD *NewThreadNamed(THREAD_PROC *thread_proc, void *param, char *name);
void ReleaseThread(THREAD *t);
void CleanupThread(THREAD *t);
void NoticeThreadInit(THREAD *t);
void WaitThreadInit(THREAD *t);
bool WaitThread(THREAD *t, UINT timeout);
void InitThreading();
void FreeThreading();
void ThreadPoolProc(THREAD *t, void *param);
void SetThreadName(UINT thread_id, char *name, void *param);

time_t c_mkgmtime(struct tm *tm);
time_t System64ToTime(UINT64 i);
void TmToSystem(SYSTEMTIME *st, struct tm *t);
void SystemToTm(struct tm *t, SYSTEMTIME *st);
void TimeToSystem(SYSTEMTIME *st, time_t t);
UINT64 TimeToSystem64(time_t t);
time_t SystemToTime(SYSTEMTIME *st);
time_t TmToTime(struct tm *t);
void TimeToTm(struct tm *t, time_t time);
void NormalizeTm(struct tm *t);
void NormalizeSystem(SYSTEMTIME *st);
void LocalToSystem(SYSTEMTIME *system, SYSTEMTIME *local);
void SystemToLocal(SYSTEMTIME *local, SYSTEMTIME *system);
INT64 GetTimeDiffEx(SYSTEMTIME *basetime, bool local_time);
void UINT64ToSystem(SYSTEMTIME *st, UINT64 sec64);
UINT64 SystemToUINT64(SYSTEMTIME *st);
UINT64 LocalTime64();
UINT64 SystemTime64();
USHORT SystemToDosDate(SYSTEMTIME *st);
USHORT System64ToDosDate(UINT64 i);
USHORT SystemToDosTime(SYSTEMTIME *st);
USHORT System64ToDosTime(UINT64 i);
void LocalTime(SYSTEMTIME *st);
void SystemTime(SYSTEMTIME *st);
void SetLocale(wchar_t *str);
bool LoadLocale(LOCALE *locale, wchar_t *str);
void GetCurrentLocale(LOCALE *locale);
void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
void GetDateStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
void GetTimeStr(char *str, UINT size, SYSTEMTIME *st);
UINT Tick();
UINT TickRealtime();
UINT TickRealtimeManual();
UINT64 TickGetRealtimeTickValue64();
UINT64 SystemToLocal64(UINT64 t);
UINT64 LocalToSystem64(UINT64 t);
UINT ThreadId();
void GetDateTimeStr64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStr64Uni(wchar_t *str, UINT size, UINT64 sec64);
void GetDateTimeStrMilli64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrMilli64ForFileName(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrMilliForFileName(char *str, UINT size, SYSTEMTIME *tm);
void GetDateStr64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64);
void GetTimeStr64(char *str, UINT size, UINT64 sec64);
UINT64 SafeTime64(UINT64 sec64);
bool Run(char *filename, char *arg, bool hide, bool wait);
bool RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
void HashInstanceName(char *name, UINT size, char *instance_name);
void HashInstanceNameLocal(char *name, UINT size, char *instance_name);
INSTANCE *NewSingleInstance(char *instance_name);
INSTANCE *NewSingleInstanceEx(char *instance_name, bool user_local);
void FreeSingleInstance(INSTANCE *inst);
void GetSpanStr(char *str, UINT size, UINT64 sec64);
void GetSpanStrEx(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetSpanStrMilli(char *str, UINT size, UINT64 sec64);
void GetMemInfo(MEMINFO *info);
bool GetEnv(char *name, char *data, UINT size);
bool GetEnvW(wchar_t *name, wchar_t *data, UINT size);
bool GetEnvW_ForWin32(wchar_t *name, wchar_t *data, UINT size);
bool GetEnvW_ForUnix(wchar_t *name, wchar_t *data, UINT size);
void GetHomeDir(char *path, UINT size);
void GetHomeDirW(wchar_t *path, UINT size);
void AbortExit();
void AbortExitEx(char *msg);
void YieldCpu();
UINT DoNothing();
LIST *NewThreadList();
void AddThreadToThreadList(LIST *o, THREAD *t);
void DelThreadFromThreadList(LIST *o, THREAD *t);
void MainteThreadList(LIST *o);
void FreeThreadList(LIST *o);
void StopThreadList(LIST *o);
void WaitAllThreadsWillBeStopped(LIST *o);

#endif	// KERNEL_H


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/

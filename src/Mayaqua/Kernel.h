// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


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

struct tm * c_gmtime_r(const time_64t* timep, struct tm *tm);
time_64t c_mkgmtime(struct tm *tm);
void TmToSystem(SYSTEMTIME *st, struct tm *t);
void SystemToTm(struct tm *t, SYSTEMTIME *st);
void TimeToSystem(SYSTEMTIME *st, time_64t t);
time_64t SystemToTime(SYSTEMTIME *st);
time_64t TmToTime(struct tm *t);
void TimeToTm(struct tm *t, time_64t time);
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
void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
void GetDateStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
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
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrRFC3339(char *str, UINT size, SYSTEMTIME *st, int timezone_min);
bool DateTimeStrRFC3339ToSystemTime(SYSTEMTIME *st, char *str);
UINT64 DateTimeStrRFC3339ToSystemTime64(char *str);
UINT64 SafeTime64(UINT64 sec64);
bool Run(char *filename, char *arg, bool hide, bool wait);
bool RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
void HashInstanceName(char *name, UINT size, char *instance_name);
void HashInstanceNameLocal(char *name, UINT size, char *instance_name);
INSTANCE *NewSingleInstance(char *instance_name);
INSTANCE *NewSingleInstanceEx(char *instance_name, bool user_local);
void FreeSingleInstance(INSTANCE *inst);
void GetSpanStrMilli(char *str, UINT size, UINT64 sec64);
void GetMemInfo(MEMINFO *info);
bool GetEnv(char *name, char *data, UINT size);
bool GetEnvW(wchar_t *name, wchar_t *data, UINT size);
bool GetEnvW_ForWin32(wchar_t *name, wchar_t *data, UINT size);
bool GetEnvW_ForUnix(wchar_t *name, wchar_t *data, UINT size);
void GetHomeDirW(wchar_t *path, UINT size);
void AbortExit();
void AbortExitEx(char *msg);
void YieldCpu();
LIST *NewThreadList();
void AddThreadToThreadList(LIST *o, THREAD *t);
void MaintainThreadList(LIST *o);
void FreeThreadList(LIST *o);
void StopThreadList(LIST *o);
UINT GetNumberOfCpu();

#endif	// KERNEL_H


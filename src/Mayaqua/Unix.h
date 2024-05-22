// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Unix.h
// Header of Unix.c

#ifdef	OS_UNIX

#ifndef	UNIX_H
#define	UNIX_H

#include "OS.h"

// Constants
#define	UNIX_THREAD_STACK_SIZE			(200 * 1000)	// Stack size
#define	UNIX_MAX_CHILD_PROCESSES		2000000			// Maximum number of child processes
#define	UNIX_LINUX_MAX_THREADS			200000000		// Maximum number of threads
#define	UNIX_MAX_LOCKS					65536			// Maximum number of locks
#define	UNIX_MAX_MEMORY					(2147483648UL)	// Maximum memory capacity
#define	UNIX_MAX_MEMORY_64				((UINT64)((UINT64)65536ULL * (UINT64)2147483647ULL))	// Maximum memory capacity (64-bit)
#define	UNIX_MAX_FD						(655360)		// Maximum number of FDs
#define	UNIX_MAX_FD_MACOS				(10000)			// Maximum number of FDs (Mac OS X)
#define	MAXIMUM_WAIT_OBJECTS			64				// Maximum number of select

#define	UNIX_SERVICE_STOP_TIMEOUT_1		(60 * 1000)	// Timeout to stop the service
#define	UNIX_SERVICE_STOP_TIMEOUT_2		(90 * 1000)	// Timeout to stop the service (parent process)


// Service related
typedef void (SERVICE_FUNCTION)();

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"

#define	UNIX_SVC_ARG_START				"start"
#define	UNIX_SVC_ARG_STOP				"stop"
#define	UNIX_SVC_ARG_EXEC_SVC			"execsvc"
#define	UNIX_ARG_EXIT					"exit"
#define UNIX_SVC_ARG_FOREGROUND				"--foreground"

#define	UNIX_SVC_MODE_START				1
#define	UNIX_SVC_MODE_STOP				2
#define	UNIX_SVC_MODE_EXEC_SVC			3
#define	UNIX_SVC_MODE_EXIT				4


// Function prototype
OS_DISPATCH_TABLE *UnixGetDispatchTable();
void UnixInit();
void UnixFree();
void *UnixMemoryAlloc(UINT size);
void *UnixMemoryReAlloc(void *addr, UINT size);
void UnixMemoryFree(void *addr);
UINT UnixGetTick();
void UnixGetSystemTime(SYSTEMTIME *system_time);
void UnixInc32(UINT *value);
void UnixDec32(UINT *value);
void UnixSleep(UINT time);
LOCK *UnixNewLock();
bool UnixLock(LOCK *lock);
void UnixUnlock(LOCK *lock);
void UnixUnlockEx(LOCK *lock, bool inner);
void UnixDeleteLock(LOCK *lock);
void UnixInitEvent(EVENT *event);
void UnixSetEvent(EVENT *event);
void UnixResetEvent(EVENT *event);
bool UnixWaitEvent(EVENT *event, UINT timeout);
void UnixFreeEvent(EVENT *event);
bool UnixWaitThread(THREAD *t);
void UnixFreeThread(THREAD *t);
bool UnixInitThread(THREAD *t);
UINT UnixThreadId();
void *UnixFileOpen(char *name, bool write_mode, bool read_lock);
void *UnixFileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *UnixFileCreate(char *name);
void *UnixFileCreateW(wchar_t *name);
void *GetUnixio4Stdout();
bool UnixFileWrite(void *pData, void *buf, UINT size);
bool UnixFileRead(void *pData, void *buf, UINT size);
void UnixFileClose(void *pData, bool no_flush);
void UnixFileFlush(void *pData);
UINT64 UnixFileSize(void *pData);
bool UnixFileSeek(void *pData, UINT mode, int offset);
bool UnixFileDelete(char *name);
bool UnixFileDeleteW(wchar_t *name);
bool UnixMakeDir(char *name);
bool UnixMakeDirW(wchar_t *name);
bool UnixDeleteDir(char *name);
bool UnixDeleteDirW(wchar_t *name);
CALLSTACK_DATA *UnixGetCallStack();
bool UnixGetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool UnixFileRename(char *old_name, char *new_name);
bool UnixFileRenameW(wchar_t *old_name, wchar_t *new_name);
bool UnixRun(char *filename, char *arg, bool hide, bool wait);
bool UnixRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool UnixIsSupportedOs();
void UnixGetOsInfo(OS_INFO *info);
void UnixAlert(char *msg, char *caption);
void UnixAlertW(wchar_t *msg, wchar_t *caption);
char *UnixGetProductId();
void UnixSetHighPriority();
void UnixSetHighOomScore();
void UnixRestorePriority();
UINT UnixGetNumberOfCpuInner();
void *UnixNewSingleInstance(char *instance_name);
void UnixFreeSingleInstance(void *data);
void UnixGetMemInfo(MEMINFO *info);
void UnixYield();
TOKEN_LIST *UnixExec(char *cmd);
void UnixExecSilent(char *cmd);
void UnixDisableInterfaceOffload(char *name);
void UnixSetEnableKernelEspProcessing(bool b);

void UnixDisableCoreDump();
void UnixSetThreadPriorityRealtime();
void UnixSetResourceLimit(UINT id, UINT64 value);
bool UnixIs64BitRlimSupported();
UINT64 UnixGetTick64();
UINT64 UnixGetHighresTickNano64(bool raw);
void UnixSigChldHandler(int sig);
void UnixCloseIO();
void UnixGetCurrentDir(char *dir, UINT size);
void UnixGetCurrentDirW(wchar_t *dir, UINT size);
bool UnixCheckExecAccess(char *name);
bool UnixCheckExecAccessW(wchar_t *name);
DIRLIST *UnixEnumDirEx(char *dirname, COMPARE *compare);
DIRLIST *UnixEnumDirExW(wchar_t *dirname, COMPARE *compare);
bool UnixGetDiskFreeMain(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool UnixGetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
void UnixInitSolarisSleep();
void UnixFreeSolarisSleep();
void UnixSolarisSleep(UINT msec);

UINT UnixService(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixServiceMain(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixGenPidFileName(char *name, UINT size);
void UnixGenCtlFileName(char *name, UINT size);
void UnixStartService(char *name);
void UnixStopService(char *name);
void UnixExecService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixUsage(char *name);
void UnixWritePidFile(UINT pid);
void UnixWriteCtlFile(UINT i);
UINT UnixReadPidFile();
UINT UnixReadCtlFile();
bool UnixIsProcess(UINT pid);
bool UnixWaitProcessEx(UINT pid, UINT timeout);
void UnixDeletePidFile();
void UnixDeleteCtlFile();
void UnixStopThread(THREAD *t, void *param);
UINT UnixGetUID();
void UnixIgnoreSignalForThread(int sig);

bool UnixIsInVmMain();
bool UnixIsInVm();


#endif	// UNIX_H

#endif	// OS_UNIX


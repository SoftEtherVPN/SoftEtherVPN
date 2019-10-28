// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// OS.h
// Header of OS.c

#ifndef	OS_H
#define	OS_H

// Function prototype
char *OsTypeToStr(UINT type);

void OSInit();
void OSFree();
void *OSMemoryAlloc(UINT size);
void *OSMemoryReAlloc(void *addr, UINT size);
void OSMemoryFree(void *addr);
UINT OSGetTick();
void OSGetSystemTime(SYSTEMTIME *system_time);
void OSSleep(UINT time);
LOCK *OSNewLock();
bool OSLock(LOCK *lock);
void OSUnlock(LOCK *lock);
void OSDeleteLock(LOCK *lock);
void OSInitEvent(EVENT *event);
void OSSetEvent(EVENT *event);
bool OSWaitEvent(EVENT *event, UINT timeout);
void OSFreeEvent(EVENT *event);
bool OSWaitThread(THREAD *t);
void OSFreeThread(THREAD *t);
bool OSInitThread(THREAD *t);
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *OSFileCreateW(wchar_t *name);
bool OSFileWrite(void *pData, void *buf, UINT size);
bool OSFileRead(void *pData, void *buf, UINT size);
void OSFileClose(void *pData, bool no_flush);
void OSFileFlush(void *pData);
UINT64 OSFileSize(void *pData);
bool OSFileSeek(void *pData, UINT mode, int offset);
bool OSFileDeleteW(wchar_t *name);
bool OSMakeDirW(wchar_t *name);
bool OSDeleteDirW(wchar_t *name);
CALLSTACK_DATA *OSGetCallStack();
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name);
UINT OSThreadId();
bool OSRun(char *filename, char *arg, bool hide, bool wait);
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool OSIsSupportedOs();
void OSGetOsInfo(OS_INFO *info);
void OSAlert(char *msg, char *caption);
void OSAlertW(wchar_t *msg, wchar_t *caption);
char* OSGetProductId();
void OSSetHighPriority();
void OSRestorePriority();
void *OSNewSingleInstance(char *instance_name);
void OSFreeSingleInstance(void *data);
void OSGetMemInfo(MEMINFO *info);
void OSYield();

// Dispatch table
typedef struct OS_DISPATCH_TABLE
{
	void (*Init)();
	void (*Free)();
	void *(*MemoryAlloc)(UINT size);
	void *(*MemoryReAlloc)(void *addr, UINT size);
	void (*MemoryFree)(void *addr);
	UINT (*GetTick)();
	void (*GetSystemTime)(SYSTEMTIME *system_time);
	void (*Inc32)(UINT *value);
	void (*Dec32)(UINT *value);
	void (*Sleep)(UINT time);
	LOCK *(*NewLock)();
	bool (*Lock)(LOCK *lock);
	void (*Unlock)(LOCK *lock);
	void (*DeleteLock)(LOCK *lock);
	void (*InitEvent)(EVENT *event);
	void (*SetEvent)(EVENT *event);
	void (*ResetEvent)(EVENT *event);
	bool (*WaitEvent)(EVENT *event, UINT timeout);
	void (*FreeEvent)(EVENT *event);
	bool (*WaitThread)(THREAD *t);
	void (*FreeThread)(THREAD *t);
	bool (*InitThread)(THREAD *t);
	UINT (*ThreadId)();
	void *(*FileOpen)(char *name, bool write_mode, bool read_lock);
	void *(*FileOpenW)(wchar_t *name, bool write_mode, bool read_lock);
	void *(*FileCreate)(char *name);
	void *(*FileCreateW)(wchar_t *name);
	bool (*FileWrite)(void *pData, void *buf, UINT size);
	bool (*FileRead)(void *pData, void *buf, UINT size);
	void (*FileClose)(void *pData, bool no_flush);
	void (*FileFlush)(void *pData);
	UINT64 (*FileSize)(void *pData);
	bool (*FileSeek)(void *pData, UINT mode, int offset);
	bool (*FileDelete)(char *name);
	bool (*FileDeleteW)(wchar_t *name);
	bool (*MakeDir)(char *name);
	bool (*MakeDirW)(wchar_t *name);
	bool (*DeleteDir)(char *name);
	bool (*DeleteDirW)(wchar_t *name);
	CALLSTACK_DATA *(*GetCallStack)();
	bool (*GetCallStackSymbolInfo)(CALLSTACK_DATA *s);
	bool (*FileRename)(char *old_name, char *new_name);
	bool (*FileRenameW)(wchar_t *old_name, wchar_t *new_name);
	bool (*Run)(char *filename, char *arg, bool hide, bool wait);
	bool (*RunW)(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
	bool (*IsSupportedOs)();
	void (*GetOsInfo)(OS_INFO *info);
	void (*Alert)(char *msg, char *caption);
	void (*AlertW)(wchar_t *msg, wchar_t *caption);
	char *(*GetProductId)();
	void (*SetHighPriority)();
	void (*RestorePriority)();
	void *(*NewSingleInstance)(char *instance_name);
	void (*FreeSingleInstance)(void *data);
	void (*GetMemInfo)(MEMINFO *info);
	void (*Yield)();
} OS_DISPATCH_TABLE;

// Include the OS-specific header
#ifdef	OS_WIN32
#include <Mayaqua/Win32.h>
#else	//OS_WIN32
#include <Mayaqua/Unix.h>
#endif	// OS_WIN32

#endif	// OS_H


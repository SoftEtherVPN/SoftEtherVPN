// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// OS.c
// Operating system dependent code

#include "OS.h"

#undef Yield

// Dispatch table
static OS_DISPATCH_TABLE *os = NULL;

// Convert OS type to a string
char *OsTypeToStr(UINT type)
{
	switch (type)
	{
	case 0:
		return "Unsupported OS by SoftEther VPN\0\n";
	case OSTYPE_WINDOWS_95:
		return "Windows 95\0\n";
	case OSTYPE_WINDOWS_98:
		return "Windows 98\0\n";
	case OSTYPE_WINDOWS_ME:
		return "Windows Millennium Edition\0\n";
	case OSTYPE_WINDOWS_UNKNOWN:
		return "Windows 9x Unknown Version\0\n";
	case OSTYPE_WINDOWS_NT_4_WORKSTATION:
		return "Windows NT 4.0 Workstation\0\n";
	case OSTYPE_WINDOWS_NT_4_SERVER:
		return "Windows NT 4.0 Server\0\n";
	case OSTYPE_WINDOWS_NT_4_SERVER_ENTERPRISE:
		return "Windows NT 4.0 Server, Enterprise Edition\0\n";
	case OSTYPE_WINDOWS_NT_4_BACKOFFICE:
		return "BackOffice Server 4.5\0\n";
	case OSTYPE_WINDOWS_NT_4_SMS:
		return "Small Business Server 4.5\0\n";
	case OSTYPE_WINDOWS_2000_PROFESSIONAL:
		return "Windows 2000 Professional\0\n";
	case OSTYPE_WINDOWS_2000_SERVER:
		return "Windows 2000 Server\0\n";
	case OSTYPE_WINDOWS_2000_ADVANCED_SERVER:
		return "Windows 2000 Advanced Server\0\n";
	case OSTYPE_WINDOWS_2000_DATACENTER_SERVER:
		return "Windows 2000 Datacenter Server\0\n";
	case OSTYPE_WINDOWS_2000_BACKOFFICE:
		return "BackOffice Server 2000\0\n";
	case OSTYPE_WINDOWS_2000_SBS:
		return "Small Business Server 2000\0\n";
	case OSTYPE_WINDOWS_XP_HOME:
		return "Windows XP Home Edition\0\n";
	case OSTYPE_WINDOWS_XP_PROFESSIONAL:
		return "Windows XP Professional\0\n";
	case OSTYPE_WINDOWS_2003_WEB:
		return "Windows Server 2003 Web Edition\0\n";
	case OSTYPE_WINDOWS_2003_STANDARD:
		return "Windows Server 2003 Standard Edition\0\n";
	case OSTYPE_WINDOWS_2003_ENTERPRISE:
		return "Windows Server 2003 Enterprise Edition\0\n";
	case OSTYPE_WINDOWS_2003_DATACENTER:
		return "Windows Server 2003 Datacenter Edition\0\n";
	case OSTYPE_WINDOWS_2003_BACKOFFICE:
		return "BackOffice Server 2003\0\n";
	case OSTYPE_WINDOWS_2003_SBS:
		return "Small Business Server 2003\0\n";
	case OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL:
		return "Windows Vista\0\n";
	case OSTYPE_WINDOWS_LONGHORN_SERVER:
		return "Windows Server 2008\0\n";
	case OSTYPE_WINDOWS_7:
		return "Windows 7\0\n";
	case OSTYPE_WINDOWS_SERVER_2008_R2:
		return "Windows Server 2008 R2\0\n";
	case OSTYPE_WINDOWS_8:
		return "Windows 8\0\n";
	case OSTYPE_WINDOWS_SERVER_8:
		return "Windows Server 2012\0\n";
	case OSTYPE_WINDOWS_81:
		return "Windows 8.1\0\n";
	case OSTYPE_WINDOWS_SERVER_81:
		return "Windows Server 2012 R2\0\n";
	case OSTYPE_WINDOWS_10:
		return "Windows 10\0\n";
	case OSTYPE_WINDOWS_SERVER_10:
		return "Windows Server 2016\0\n";
	case OSTYPE_WINDOWS_11:
		return "Newer than Windows 10\0\n";
	case OSTYPE_WINDOWS_SERVER_11:
		return "Newer than Windows Server 2016\0\n";
	case OSTYPE_UNIX_UNKNOWN:
		return "UNIX System\0\n";
	case OSTYPE_LINUX:
		return "Linux\0\n";
	case OSTYPE_SOLARIS:
		return "Sun Solaris\0\n";
	case OSTYPE_CYGWIN:
		return "Gnu Cygwin\0\n";
	case OSTYPE_BSD:
		return "BSD System\0\n";
	case OSTYPE_MACOS_X:
		return "Mac OS X\0\n";
	}

	return "Unknown OS";
}

// Initialization
void OSInit()
{
	// Get the dispatch table
#ifdef	OS_WIN32
	os = Win32GetDispatchTable();
#else	// OS_WIN32
	os = UnixGetDispatchTable();
#endif	// OS_WIN32

	// Calling the OS-specific initialization function
	os->Init();
}

// Release
void OSFree()
{
	os->Free();
}

// Get the memory information
void OSGetMemInfo(MEMINFO *info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	os->GetMemInfo(info);
}

// Yield
void OSYield()
{
	os->Yield();
}

// Start a Single instance
void *OSNewSingleInstance(char *instance_name)
{
	return os->NewSingleInstance(instance_name);
}

void OSFreeSingleInstance(void *data)
{
	os->FreeSingleInstance(data);
}

// Raise the priority
void OSSetHighPriority()
{
	os->SetHighPriority();
}

// Restore the priority
void OSRestorePriority()
{
	os->RestorePriority();
}

// Get the product ID
char* OSGetProductId()
{
	return os->GetProductId();
}

// Check whether the OS is supported
bool OSIsSupportedOs()
{
	return os->IsSupportedOs();
}

// Getting OS information
void OSGetOsInfo(OS_INFO *info)
{
	os->GetOsInfo(info);
}

// Show an alert
void OSAlert(char *msg, char *caption)
{
	os->Alert(msg, caption);
}
void OSAlertW(wchar_t *msg, wchar_t *caption)
{
	os->AlertW(msg, caption);
}

// Run a process
bool OSRun(char *filename, char *arg, bool hide, bool wait)
{
	return os->Run(filename, arg, hide, wait);
}
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	return os->RunW(filename, arg, hide, wait);
}

// Get the Thread ID
UINT OSThreadId()
{
	return os->ThreadId();
}

// Rename
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	return os->FileRenameW(old_name, new_name);
}

// Get the file size
UINT64 OSFileSize(void *pData)
{
	return os->FileSize(pData);
}

// Seek the file
bool OSFileSeek(void *pData, UINT mode, int offset)
{
	return os->FileSeek(pData, mode, offset);
}

// Delete the file
bool OSFileDeleteW(wchar_t *name)
{
	return os->FileDeleteW(name);
}

// Create a directory
bool OSMakeDirW(wchar_t *name)
{
	return os->MakeDirW(name);
}

// Delete the directory
bool OSDeleteDirW(wchar_t *name)
{
	return os->DeleteDirW(name);
}

// Open the file
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	return os->FileOpenW(name, write_mode, read_lock);
}

// Create a file
void *OSFileCreateW(wchar_t *name)
{
	return os->FileCreateW(name);
}

// Write to a file
bool OSFileWrite(void *pData, void *buf, UINT size)
{
	return os->FileWrite(pData, buf, size);
}

// Read from a file
bool OSFileRead(void *pData, void *buf, UINT size)
{
	return os->FileRead(pData, buf, size);
}

// Close the file
void OSFileClose(void *pData, bool no_flush)
{
	os->FileClose(pData, no_flush);
}

// Flush to the file
void OSFileFlush(void *pData)
{
	os->FileFlush(pData);
}

// Get the call stack
CALLSTACK_DATA *OSGetCallStack()
{
	return os->GetCallStack();
}

// Get the symbol information
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	return os->GetCallStackSymbolInfo(s);
}

// Wait for the termination of the thread
bool OSWaitThread(THREAD *t)
{
	return os->WaitThread(t);
}

// Release of thread
void OSFreeThread(THREAD *t)
{
	os->FreeThread(t);
}

// Thread initialization
bool OSInitThread(THREAD *t)
{
	return os->InitThread(t);
}

// Memory allocation
void *OSMemoryAlloc(UINT size)
{
	return os->MemoryAlloc(size);
}

// Memory reallocation
void *OSMemoryReAlloc(void *addr, UINT size)
{
	return os->MemoryReAlloc(addr, size);
}

// Memory release
void OSMemoryFree(void *addr)
{
	os->MemoryFree(addr);
}

// Get the system timer
UINT OSGetTick()
{
	return os->GetTick();
}

// Get the System Time
void OSGetSystemTime(SYSTEMTIME *system_time)
{
	os->GetSystemTime(system_time);
}

// Sleep the thread
void OSSleep(UINT time)
{
	os->Sleep(time);
}

// Create a Lock
LOCK *OSNewLock()
{
	return os->NewLock();
}

// Lock
bool OSLock(LOCK *lock)
{
	return os->Lock(lock);
}

// Unlock
void OSUnlock(LOCK *lock)
{
	os->Unlock(lock);
}

// Delete the lock
void OSDeleteLock(LOCK *lock)
{
	os->DeleteLock(lock);
}

// Event initialization
void OSInitEvent(EVENT *event)
{
	os->InitEvent(event);
}

// Set event
void OSSetEvent(EVENT *event)
{
	os->SetEvent(event);
}

// Wait for event
bool OSWaitEvent(EVENT *event, UINT timeout)
{
	return os->WaitEvent(event, timeout);
}

// Release of the event
void OSFreeEvent(EVENT *event)
{
	os->FreeEvent(event);
}

